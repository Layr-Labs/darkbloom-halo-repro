//! The approved workflows, built in code (never from consumer input).
//!
//! The consumer chooses a workflow by name and supplies parameters; the
//! prompt is only ever placed into a JSON string value, so a prompt cannot
//! alter the graph. Graphs are encoded like Go's `json.Marshal` of the Go
//! reference's `map[string]any` graphs (sorted keys, Go escaping), so the
//! workflow hashes agree with the Go adapter.

use db_wire::{JobRequest, ModelCap};
use serde::Serialize;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

/// An approved model and the workflow that drives it.
pub(crate) struct ComfyModel {
    pub(crate) id: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) workflow: &'static str,
    pub(crate) max_width: i64,
    pub(crate) max_height: i64,
    pub(crate) max_steps: i64,
    pub(crate) max_frames: i64,
    /// Files relative to a models root.
    pub(crate) files: &'static [&'static str],
    pub(crate) graph: fn(&JobRequest, &str) -> Value,
    pub(crate) video: bool,
    /// The workflow consumes an input image (image-to-image, image-to-video).
    pub(crate) takes_image: bool,
}

/// The approved models, in the Go reference's order.
pub(crate) static MODELS: [ComfyModel; 2] = [
    ComfyModel {
        id: "z-image-turbo",
        kind: "image",
        workflow: "z-image-turbo-t2i",
        max_width: 2048,
        max_height: 2048,
        max_steps: 16,
        max_frames: 0,
        files: &["diffusion_models/z_image_turbo_bf16.safetensors", "text_encoders/qwen_3_4b.safetensors", "vae/ae.safetensors"],
        graph: z_image_turbo_graph,
        video: false,
        takes_image: false,
    },
    ComfyModel {
        id: "wan2.1-t2v-1.3b",
        kind: "video",
        workflow: "wan2.1-t2v",
        max_width: 832,
        max_height: 480,
        max_steps: 30,
        max_frames: 81,
        files: &[
            "diffusion_models/wan2.1_t2v_1.3B_fp16.safetensors",
            "text_encoders/umt5_xxl_fp8_e4m3fn_scaled.safetensors",
            "vae/wan_2.1_vae.safetensors",
        ],
        graph: wan_t2v_graph,
        video: true,
        takes_image: false,
    },
];

impl ComfyModel {
    /// What the engine advertises for this model.
    pub(crate) fn cap(&self) -> ModelCap {
        ModelCap {
            id: self.id.to_owned(),
            kind: self.kind.to_owned(),
            workflows: vec![self.workflow.to_owned()],
            max_width: self.max_width,
            max_height: self.max_height,
            max_steps: self.max_steps,
            max_frames: self.max_frames,
            max_tokens: 0,
        }
    }

    /// Identifies the workflow's structure: SHA-256 (hex) of the graph
    /// built with neutral parameters (a zero request, empty prefix),
    /// encoded like Go's `json.Marshal` (Go `workflowHash`).
    pub(crate) fn workflow_hash(&self) -> String {
        let graph = (self.graph)(&JobRequest::default(), "");
        match db_gojson::to_vec(&Sorted(&graph)) {
            Ok(b) => hex::encode(Sha256::digest(&b)),
            // Encoding a plain JSON value cannot fail.
            Err(_) => String::new(),
        }
    }
}

/// The Wan 2.1 template's default negative prompt.
pub(crate) const WAN_NEGATIVE: &str = "色调艳丽，过曝，静态，细节模糊不清，字幕，风格，作品，画作，画面，静止，整体发灰，最差质量，低质量，JPEG压缩残留，丑陋的，残缺的，多余的手指，画得不好的手部，画得不好的脸部，畸形的，毁容的，形态畸形的肢体，手指融合，静止不动的画面，杂乱的背景，三条腿，背景人很多，倒着走";

fn node(class: &str, inputs: Value) -> Value {
    json!({"class_type": class, "inputs": inputs})
}

/// ComfyUI's official Z-Image-Turbo text-to-image template
/// (comfyui-workflow-templates `image_z_image_turbo`) in API form.
fn z_image_turbo_graph(req: &JobRequest, prefix: &str) -> Value {
    json!({
        "28": node("UNETLoader", json!({"unet_name": "z_image_turbo_bf16.safetensors", "weight_dtype": "default"})),
        "30": node("CLIPLoader", json!({"clip_name": "qwen_3_4b.safetensors", "type": "lumina2", "device": "default"})),
        "29": node("VAELoader", json!({"vae_name": "ae.safetensors"})),
        "11": node("ModelSamplingAuraFlow", json!({"model": ["28", 0], "shift": 3})),
        "27": node("CLIPTextEncode", json!({"clip": ["30", 0], "text": Value::String(req.prompt.clone())})),
        "33": node("ConditioningZeroOut", json!({"conditioning": ["27", 0]})),
        "13": node("EmptySD3LatentImage", json!({"width": req.width, "height": req.height, "batch_size": 1})),
        "3": node("KSampler", json!({
            "model": ["11", 0], "positive": ["27", 0], "negative": ["33", 0], "latent_image": ["13", 0],
            "seed": req.seed, "steps": req.steps, "cfg": 1, "sampler_name": "res_multistep", "scheduler": "simple",
            "denoise": 1,
        })),
        "8": node("VAEDecode", json!({"samples": ["3", 0], "vae": ["29", 0]})),
        "9": node("SaveImage", json!({"images": ["8", 0], "filename_prefix": prefix})),
    })
}

/// ComfyUI's official Wan 2.1 text-to-video template (`text_to_video_wan`)
/// in API form; the result is an MP4.
fn wan_t2v_graph(req: &JobRequest, prefix: &str) -> Value {
    let neg = if req.negative_prompt.is_empty() { WAN_NEGATIVE } else { req.negative_prompt.as_str() };
    json!({
        "37": node("UNETLoader", json!({"unet_name": "wan2.1_t2v_1.3B_fp16.safetensors", "weight_dtype": "default"})),
        "38": node("CLIPLoader", json!({"clip_name": "umt5_xxl_fp8_e4m3fn_scaled.safetensors", "type": "wan", "device": "default"})),
        "39": node("VAELoader", json!({"vae_name": "wan_2.1_vae.safetensors"})),
        "48": node("ModelSamplingSD3", json!({"model": ["37", 0], "shift": 8})),
        "6": node("CLIPTextEncode", json!({"clip": ["38", 0], "text": Value::String(req.prompt.clone())})),
        "7": node("CLIPTextEncode", json!({"clip": ["38", 0], "text": Value::String(neg.to_owned())})),
        "40": node("EmptyHunyuanLatentVideo", json!({"width": req.width, "height": req.height, "length": req.frames, "batch_size": 1})),
        "3": node("KSampler", json!({
            "model": ["48", 0], "positive": ["6", 0], "negative": ["7", 0], "latent_image": ["40", 0],
            "seed": req.seed, "steps": req.steps, "cfg": 6, "sampler_name": "uni_pc", "scheduler": "simple",
            "denoise": 1,
        })),
        "8": node("VAEDecode", json!({"samples": ["3", 0], "vae": ["39", 0]})),
        "49": node("CreateVideo", json!({"images": ["8", 0], "fps": req.fps})),
        "50": node("SaveVideo", json!({"video": ["49", 0], "filename_prefix": prefix, "format": "mp4"})),
    })
}

/// Serializes a JSON value with object keys in byte order, as Go's
/// encoding/json writes maps, whatever map type serde_json was built with.
pub(crate) struct Sorted<'a>(pub(crate) &'a Value);

impl Serialize for Sorted<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(m) => {
                let mut entries: Vec<(&String, &Value)> = m.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    map.serialize_entry(k, &Sorted(v))?;
                }
                map.end()
            }
            Value::Array(a) => {
                let mut seq = s.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(&Sorted(v))?;
                }
                seq.end()
            }
            other => other.serialize(s),
        }
    }
}

/// Overwrites every string in a graph (prompts) before it is dropped.
pub(crate) fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => m.values_mut().for_each(wipe),
        _ => {}
    }
}
