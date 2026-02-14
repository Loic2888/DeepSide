use ort::session::Session;
use ort::value::Value;
use tokenizers::Tokenizer;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::path::Path;
use std::fs;

// Global state for reuse
static AI_ENGINE: Lazy<Mutex<Option<AiEngine>>> = Lazy::new(|| Mutex::new(None));

struct AiEngine {
    session: Session,
    tokenizer: Tokenizer,
}

#[derive(serde::Serialize, Clone)]
pub struct AiStatus {
    pub loaded: bool,
    pub model_path: Option<String>,
    pub error: Option<String>,
}

/// Initialize the ONNX engine with model path
pub fn init_onnx<P: AsRef<Path>>(model_path: P, tokenizer_path: P) -> Result<(), String> {
    println!("Initializing ONNX Engine (v2.0-rc.9)...");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    
    // 1. Load Tokenizer
    println!("Loading Tokenizer from {:?}...", tokenizer_path.as_ref());
    std::io::stdout().flush().unwrap();
    
    let tokenizer = Tokenizer::from_file(&tokenizer_path)
        .map_err(|e| format!("Failed to load tokenizer: {}", e))?;
    
    println!("Tokenizer loaded. Creating Session builder...");
    std::io::stdout().flush().unwrap();

    // 2. Load ONNX Model directly from file (avoid reading into memory to prevent stack/heap overflow)
    let builder = Session::builder()
        .map_err(|e| format!("Failed to create session builder: {}", e))?;
        
    println!("Setting intra_threads...");
    std::io::stdout().flush().unwrap();
    
    let builder = builder.with_intra_threads(4)
        .map_err(|e| format!("Failed to set threads: {}", e))?;
        
    println!("Committing model from file: {:?}", model_path.as_ref());
    std::io::stdout().flush().unwrap();
    
    let model = builder.commit_from_file(&model_path)
        .map_err(|e| format!("Failed to load model from file: {}", e))?;

    println!("ONNX Model loaded successfully!");
    std::io::stdout().flush().unwrap();

    // 4. Store in Global State
    *AI_ENGINE.lock().unwrap() = Some(AiEngine { session: model, tokenizer });
    
    Ok(())
}

/// Run inference on a prompt (Generative Loop)
pub fn run_inference(prompt: &str) -> Result<String, String> {
    let mut engine_lock = AI_ENGINE.lock().unwrap();
    let engine = engine_lock.as_mut().ok_or("AI Engine not initialized")?;

    // 1. Tokenize the input
    let mut tokens: Vec<u32> = engine.tokenizer
        .encode(prompt, true)
        .map_err(|e| format!("Tokenization failed: {}", e))?
        .get_ids()
        .to_vec();

    let mut generated_text = String::new();
    let max_new_tokens = 150; 
    
    // Stop tokens for common models (Phi-3 uses 32000, 32007; Llama uses 128001, etc.)
    let stop_tokens = [32000, 32001, 32007, 32008, 32009];

    for step in 0..max_new_tokens {
        let seq_len = tokens.len();
        if seq_len > 1024 { break; } // Context limit

        let input_ids: Vec<i64> = tokens.iter().map(|&id| id as i64).collect();
        
        // Position IDs: [0, 1, 2, ..., seq_len-1]
        let position_ids: Vec<i64> = (0..seq_len).map(|i| i as i64).collect();

        // 2. Create input tensors
        let input_ids_value = Value::from_array(([1usize, seq_len], input_ids))
            .map_err(|e| format!("Input ids creation error: {}", e))?;

        let position_ids_value = Value::from_array(([1usize, seq_len], position_ids))
            .map_err(|e| format!("Position IDs creation error: {}", e))?;

        // Prepare attention mask with dummy past (prepend 0)
        // Dummy past length is 1 (fixed in this simple implementation)
        let mut attention_mask = vec![0i64; 1];
        attention_mask.extend(std::iter::repeat(1i64).take(seq_len));
        let total_mask_len = attention_mask.len();

        let attention_value = Value::from_array(([1usize, total_mask_len], attention_mask))
            .map_err(|e| format!("Attention mask creation error: {}", e))?;

        use std::borrow::Cow;
        let mut inputs: Vec<(Cow<'static, str>, Value)> = vec![
            (Cow::Borrowed("input_ids"), input_ids_value.into()),
            (Cow::Borrowed("attention_mask"), attention_value.into()),
            (Cow::Borrowed("position_ids"), position_ids_value.into()),
        ];

        // Add dummy past_key_values for 22/32 layers (Model specific)
        // Some exports want (1, 4, 1, 64) dummy zeros for the first pass or if not using cache properly
        for i in 0..32 { // Support up to 32 layers (Phi-3 Mini is 32, not 22)
            let shape = [1usize, 4, 1, 64];
            let data: Vec<f32> = vec![0.0; 1 * 4 * 1 * 64];
            
            let key_name = format!("past_key_values.{}.key", i);
            let key_val = Value::from_array((shape, data.clone()))
                 .map_err(|e| format!("Past Key {} creation error: {}", i, e))?;
            
            let val_name = format!("past_key_values.{}.value", i);
            let val_val = Value::from_array((shape, data))
                 .map_err(|e| format!("Past Value {} creation error: {}", i, e))?;

            inputs.push((Cow::Owned(key_name), key_val.into()));
            inputs.push((Cow::Owned(val_name), val_val.into()));
        }

        // Run inference
        let outputs = match engine.session.run(inputs) {
            Ok(o) => o,
            Err(e) => {
                // If it failed because of layer count (e.g. 22 vs 32), we could potentially retry
                // but for now just return error
                return Err(format!("Inference failed at step {}: {}", step, e));
            }
        };

        // Get logits from outputs[0]
        let (shape, output_data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| format!("Output extraction failed: {}", e))?;

        let vocab_size = shape[2] as usize;
        let last_token_idx = (shape[1] - 1) as usize;
        let start_offset = last_token_idx * vocab_size;
        
        let last_token_logits = &output_data[start_offset..start_offset + vocab_size];

        // Greedy decoding
        let mut max_val = f32::MIN;
        let mut next_token_id = 0;
        for (id, &val) in last_token_logits.iter().enumerate() {
            if val > max_val {
                max_val = val;
                next_token_id = id as u32;
            }
        }

        // Check for stop tokens
        if stop_tokens.contains(&next_token_id) {
            break;
        }

        tokens.push(next_token_id);
        
        // Decode and append immediately to avoid huge latency
        let decoded = engine.tokenizer.decode(&[next_token_id], true)
            .unwrap_or_default();
        
        generated_text.push_str(&decoded);

        // Early exit if we have generated significant content and see typical markers
        if step > 20 && (generated_text.contains("<|end|>") || generated_text.contains("<|assistant|>")) {
            break;
        }
    }

    Ok(generated_text.trim().to_string())
}


pub fn check_status() -> AiStatus {
    let engine_lock = AI_ENGINE.lock().unwrap();
    AiStatus {
        loaded: engine_lock.is_some(),
        model_path: None, 
        error: None,
    }
}
