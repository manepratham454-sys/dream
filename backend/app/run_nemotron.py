from openai import OpenAI

client = OpenAI(
  base_url = "https://integrate.api.nvidia.com/v1",
  api_key = "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"
)

completion = client.chat.completions.create(
  model="nvidia/nemotron-3-nano-30b-a3b",
  messages=[{"role":"user","content":""}],
  temperature=1,
  top_p=1,
  max_tokens=16384,
  extra_body={"reasoning_budget":16384},
  stream=True
)

for chunk in completion:
  if not chunk.choices:
    continue
  if chunk.choices[0].delta.content is not None:
    print(chunk.choices[0].delta.content, end="")
