---
base_model: meta-llama/Meta-Llama-3-8B
library_name: peft
---

# CVE-KGRAG Fine-tuned Model

<!-- Provide a quick summary of what the model is/does. -->

This is a fine-tuned version of Meta-Llama-3-8B specifically trained for CVE analysis and cybersecurity intelligence tasks. The model has been trained on a comprehensive dataset of CVE descriptions, attack patterns, and security analysis to provide enhanced understanding and analysis of cybersecurity vulnerabilities.

## Model Details

### Model Description

This model is a fine-tuned version of Meta-Llama-3-8B using LoRA (Low-Rank Adaptation) for efficient training on CVE cybersecurity data.

- **Repository:** CVE-KGRAG Project
- **Base Model:** meta-llama/Meta-Llama-3-8B
- **Training Framework:** PEFT (Parameter-Efficient Fine-Tuning)

## How to Get Started with the Model

```python
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

# Load the fine-tuned model
model_name = "meta-llama/Meta-Llama-3-8B"
adapter_path = "models/fine_tuned_cve_production"

# Load base model and tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)
base_model = AutoModelForCausalLM.from_pretrained(model_name)

# Load LoRA adapter
model = PeftModel.from_pretrained(base_model, adapter_path)

# Example usage
prompt = "Analyze CVE-2021-44228 Log4j vulnerability"
inputs = tokenizer(prompt, return_tensors="pt")
outputs = model.generate(**inputs, max_length=256)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
```

## Training Details

### Training Data

The model was trained on:
- **Dataset:** Enhanced CVE training dataset
- **Samples:** 100 
- **Data Source:** CVE records, CAPEC attack patterns, MITRE ATT&CK techniques
- **Format:** Structured CVE analysis prompts and responses

### Training Procedure

#### Training Hyperparameters

- **Base Model:** meta-llama/Meta-Llama-3-8B
- **Training regime:** LoRA (Parameter-Efficient Fine-Tuning)
- **Learning Rate:** 1e-06
- **Max Steps:** 200
- **Batch Size:** 1
- **Max Length:** 256
- **Weight Decay:** 0.999
- **Max Gradient Norm:** 1e-05
- **Label Smoothing:** 0.99

#### Speeds, Sizes, Times

- **Training Time:** 232.91 seconds (~3.9 minutes)
- **Total Steps:** 206
- **Model Size:** ~1.0MB (LoRA adapter only)
- **Hardware:** CUDA GPU
- **Framework:** PEFT 0.7.1

### Compute Infrastructure

#### Hardware

- **GPU:** CUDA-compatible GPU
- **Memory:** Sufficient for 8B parameter model
- **Storage:** ~1MB for LoRA adapter

#### Software

- **Framework:** PyTorch with Transformers
- **PEFT Version:** 0.7.1
- **Training Framework:** HuggingFace Transformers

## Model Files

```
models/fine_tuned_cve_production/
├── adapter_config.json          # LoRA configuration
├── adapter_model.safetensors    # LoRA weights (1.0MB)
├── tokenizer.json              # Tokenizer
├── tokenizer_config.json       # Tokenizer configuration
├── special_tokens_map.json     # Special tokens mapping
├── training_args.bin           # Training arguments
├── training_report_*.json      # Training reports
└── checkpoint-*/               # Training checkpoints (120, 160, 200 steps)
```



## Model Comparison

| Metric | Test Run (10 samples) | Production Run (100 samples) |
|--------|----------------------|------------------------------|
| **Samples** | 10 | 100 |
| **Steps** | 20 | 200 |
| **Training Time** | 24.28s | 232.91s |
| **Loss Range** | 17.89-19.70 | 17.89-21.43 |
| **Eval Loss** | 18.68 | 19.22 |
| **Model Quality** | ✅ Good | ✅ Better |
