# LeroPickle — LeRobot learner gRPC `SendInteractions` pickle deserialization RCE
#
# This module contains the VULNERABLE code, copied VERBATIM from the real
# HuggingFace LeRobot repository so the PoC drives the actual defective logic.
#
#   repo   : https://github.com/huggingface/lerobot
#   commit : 6e3b67c5f0b77c93a5179d88d7c1d6a5f7ff7b27  (main, 2026-11-04)
#
# Provenance of every verbatim block is marked with  [VERBATIM ...]  banners.
# The only functions omitted are `state_to_bytes` / `bytes_to_state_dict` /
# `bytes_to_transitions` from `src/lerobot/transport/utils.py`, which are the
# torch-dependent (weights_only=True) helpers NOT on the vulnerable path; they
# are quoted in the README to show the contrast (they use the safe loader, the
# interaction-message path uses raw pickle.load).
import io
import logging
import pickle  # nosec B403: Safe usage for internal serialization only
from multiprocessing.synchronize import Event as MpEvent
from queue import Queue
from typing import Any

# Real generated protobuf from the repo (verbatim copy in ./lerobot/transport/).
from lerobot.transport import services_pb2

TransferState = services_pb2.TransferState

# [VERBATIM src/lerobot/transport/utils.py:34-47] (CHUNK_SIZE / MAX_MESSAGE_SIZE / bytes_buffer_size)
CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_MESSAGE_SIZE = 4 * 1024 * 1024  # 4 MB


def bytes_buffer_size(buffer: io.BytesIO) -> int:
    buffer.seek(0, io.SEEK_END)
    result = buffer.tell()
    buffer.seek(0)
    return result


# [VERBATIM src/lerobot/transport/utils.py:52-72] send_bytes_in_chunks
def send_bytes_in_chunks(buffer: bytes, message_class: Any, log_prefix: str = "", silent: bool = True):
    bytes_buffer: io.BytesIO = io.BytesIO(buffer)
    size_in_bytes = bytes_buffer_size(bytes_buffer)

    sent_bytes = 0

    logging_method = logging.info if not silent else logging.debug

    logging_method(f"{log_prefix} Buffer size {size_in_bytes / 1024 / 1024} MB with")

    while sent_bytes < size_in_bytes:
        transfer_state = TransferState.TRANSFER_MIDDLE

        if sent_bytes + CHUNK_SIZE >= size_in_bytes:
            transfer_state = TransferState.TRANSFER_END
        elif sent_bytes == 0:
            transfer_state = TransferState.TRANSFER_BEGIN

        size_to_read = min(CHUNK_SIZE, size_in_bytes - sent_bytes)
        chunk = bytes_buffer.read(size_to_read)

        yield message_class(transfer_state=transfer_state, data=chunk)
        sent_bytes += size_to_read
        logging_method(f"{log_prefix} Sent {sent_bytes}/{size_in_bytes} bytes with state {transfer_state}")

    logging_method(f"{log_prefix} Published {sent_bytes / 1024 / 1024} MB")


# [VERBATIM src/lerobot/transport/utils.py:77-118] receive_bytes_in_chunks
def receive_bytes_in_chunks(iterator, queue: Queue | None, shutdown_event: MpEvent, log_prefix: str = ""):
    bytes_buffer = io.BytesIO()
    step = 0

    logging.info(f"{log_prefix} Starting receiver")
    for item in iterator:
        logging.debug(f"{log_prefix} Received item")
        if shutdown_event.is_set():
            logging.info(f"{log_prefix} Shutting down receiver")
            return

        if item.transfer_state == TransferState.TRANSFER_BEGIN:
            bytes_buffer.seek(0)
            bytes_buffer.truncate(0)
            bytes_buffer.write(item.data)
            logging.debug(f"{log_prefix} Received data at step 0")
            step = 0
        elif item.transfer_state == TransferState.TRANSFER_MIDDLE:
            bytes_buffer.write(item.data)
            step += 1
            logging.debug(f"{log_prefix} Received data at step {step}")
        elif item.transfer_state == TransferState.TRANSFER_END:
            bytes_buffer.write(item.data)
            logging.debug(f"{log_prefix} Received data at step end size {bytes_buffer_size(bytes_buffer)}")

            if queue is not None:
                queue.put(bytes_buffer.getvalue())
            else:
                return bytes_buffer.getvalue()

            bytes_buffer.seek(0)
            bytes_buffer.truncate(0)
            step = 0

            logging.debug(f"{log_prefix} Queue updated")
        else:
            logging.warning(f"{log_prefix} Received unknown transfer state {item.transfer_state}")
            raise ValueError(f"Received unknown transfer state {item.transfer_state}")


# [VERBATIM src/lerobot/transport/utils.py:132-133] python_object_to_bytes
def python_object_to_bytes(python_object: Any) -> bytes:
    return pickle.dumps(python_object)


# [VERBATIM src/lerobot/transport/utils.py:136-141] bytes_to_python_object  <-- THE SINK
def bytes_to_python_object(buffer: bytes) -> Any:
    bytes_buffer = io.BytesIO(buffer)
    bytes_buffer.seek(0)
    obj = pickle.load(bytes_buffer)  # nosec B301: Safe usage of pickle.load
    # Add validation checks here
    return obj


# [VERBATIM src/lerobot/rl/learner.py:946-959] process_interaction_message (consumer)
def process_interaction_message(
    message, interaction_step_shift: int, trackio_logger=None
):
    """Process a single interaction message with consistent handling."""
    message = bytes_to_python_object(message)
    # Shift interaction step for consistency with checkpointed state
    message["Interaction step"] += interaction_step_shift

    # Log if logger available
    if trackio_logger:
        trackio_logger.log_dict(d=message, mode="train", custom_step_key="Interaction step")

    return message


# [VERBATIM src/lerobot/rl/learner_service.py:45-126] LearnerService
# (imports trimmed to the exact symbols used; method bodies are verbatim)
import grpc
from lerobot.transport import services_pb2_grpc

MAX_WORKERS = 3  # Stream parameters, send transitions and interactions
SHUTDOWN_TIMEOUT = 10


class LearnerService(services_pb2_grpc.LearnerServiceServicer):
    """
    Implementation of the LearnerService gRPC service
    This service is used to send parameters to the Actor and receive transitions and interactions from the Actor
    check transport.proto for the gRPC service definition
    """

    def __init__(
        self,
        shutdown_event,
        parameters_queue: Queue,
        seconds_between_pushes: float,
        transition_queue: Queue,
        interaction_message_queue: Queue,
        queue_get_timeout: float = 0.001,
    ):
        self.shutdown_event = shutdown_event
        self.parameters_queue = parameters_queue
        self.seconds_between_pushes = seconds_between_pushes
        self.transition_queue = transition_queue
        self.interaction_message_queue = interaction_message_queue
        self.queue_get_timeout = queue_get_timeout

    def StreamParameters(self, request, context):
        # TODO: authorize the request
        logging.info("[LEARNER] Received request to stream parameters from the Actor")

        last_push_time = 0

        while not self.shutdown_event.is_set():
            time_since_last_push = time.time() - last_push_time
            if time_since_last_push < self.seconds_between_pushes:
                self.shutdown_event.wait(self.seconds_between_pushes - time_since_last_push)
                continue

            logging.info("[LEARNER] Push parameters to the Actor")
            buffer = get_last_item_from_queue(
                self.parameters_queue, block=True, timeout=self.queue_get_timeout
            )

            if buffer is None:
                continue

            yield from send_bytes_in_chunks(
                buffer,
                services_pb2.Parameters,
                log_prefix="[LEARNER] Sending parameters",
                silent=True,
            )

            last_push_time = time.time()
            logging.info("[LEARNER] Parameters sent")

        logging.info("[LEARNER] Stream parameters finished")
        return services_pb2.Empty()

    def SendTransitions(self, request_iterator, _context):
        # TODO: authorize the request
        logging.info("[LEARNER] Received request to receive transitions from the Actor")

        receive_bytes_in_chunks(
            request_iterator,
            self.transition_queue,
            self.shutdown_event,
            log_prefix="[LEARNER] transitions",
        )

        logging.debug("[LEARNER] Finished receiving transitions")
        return services_pb2.Empty()

    def SendInteractions(self, request_iterator, _context):
        # TODO: authorize the request
        logging.info("[LEARNER] Received request to receive interactions from the Actor")

        receive_bytes_in_chunks(
            request_iterator,
            self.interaction_message_queue,
            self.shutdown_event,
            log_prefix="[LEARNER] interactions",
        )

        logging.debug("[LEARNER] Finished receiving interactions")
        return services_pb2.Empty()

    def Ready(self, request, context):
        return services_pb2.Empty()


# `time` and `get_last_item_from_queue` are only used by StreamParameters
# (not the vulnerable path); provided here for the class to parse correctly.
import time


def get_last_item_from_queue(queue: Queue, block=True, timeout: float = 0.1):
    # Minimal stdlib stand-in for lerobot.rl.queue.get_last_item_from_queue
    # (the real one uses torch.multiprocessing.Queue; only StreamParameters
    # calls it, which is NOT exercised by this PoC).
    from queue import Empty
    try:
        item = queue.get(timeout=timeout) if block else None
    except Empty:
        return None
    while not queue.empty():
        try:
            item = queue.get_nowait()
        except Empty:
            break
    return item
