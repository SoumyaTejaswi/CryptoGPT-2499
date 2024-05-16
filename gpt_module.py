# gpt_module.py
from transformers import GPT2LMHeadModel, GPT2Tokenizer

class GPTModel:
    def __init__(self, model_name_or_path):
        self.tokenizer = GPT2Tokenizer.from_pretrained(model_name_or_path)
        self.tokenizer.pad_token = self.tokenizer.eos_token  # Set pad token to eos token
        self.model = GPT2LMHeadModel.from_pretrained(model_name_or_path)

    def get_suggestion(self, text):
        input_ids = self.tokenizer.encode(text, return_tensors="pt", padding=True, truncation=True)
        attention_mask = input_ids.ne(self.tokenizer.pad_token_id)  # Set attention mask
        output = self.model.generate(input_ids, max_length=350, num_return_sequences=1, attention_mask=attention_mask)
        suggestion = self.tokenizer.decode(output[0], skip_special_tokens=True)
        return suggestion

    def get_encryption_suggestion(self, plaintext, key):
        text = f"Encrypt the plaintext '{plaintext}' using the key '{key}'."
        return self.get_suggestion(text)

    def get_decryption_suggestion(self, ciphertext, key):
        text = f"Decrypt the ciphertext '{ciphertext}' using the key '{key}'."
        return self.get_suggestion(text)

gpt_model = GPTModel("gpt2-medium")
