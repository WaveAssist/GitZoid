from openai import OpenAI
import waveassist

# Constants
TOKEN_MULTIPLIER = 2.5

# Initialize WaveAssist
waveassist.init()

def _init_openrouter_client():
    """
    Initialize and validate the OpenRouter client via the OpenAI SDK.
    """
    key = waveassist.fetch_data("open_router_key")
    if not key:
        print("⚠️ No OpenRouter API key found.")
        return None
    if not key.startswith("sk-"):
        print("❌ Invalid OpenRouter API key format.")
        return None
    # point at OpenRouter’s OpenAI‐compatible endpoint
    client = OpenAI(
        api_key=key,
        base_url="https://openrouter.ai/api/v1"
    )
    return client

# Create the client
openai_client = _init_openrouter_client()
if not openai_client:
    raise RuntimeError("❌ OpenRouter client initialization failed.")
print("✅ OpenRouter client ready.")

def format_changed_files(files, max_chars=25000):
    """Format file diffs into blocks, capping total length at max_chars."""
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        max_chars = 25000

    blocks, total = [], 0
    for idx, f in enumerate(files, 1):
        block = f"{idx}. Filename: `{f['filename']}`\n```\n{f['patch']}\n```"
        length = len(block)
        blocks.append((length, block))

    blocks.sort(key=lambda x: x[0])
    included, remaining = [], []

    for length, block in blocks:
        if total + length <= max_chars:
            included.append(block)
            total += length
        else:
            remaining.append((length, block))

    if remaining:
        budget = (max_chars - total) + int(0.1 * max_chars)
        per_block = budget // len(remaining)
        for _, block in remaining:
            truncated = block.split("```", 1)[1][: per_block - 100]
            included.append(f"...\n```{truncated}\n... (truncated)\n```")

    return "\n\n".join(included)

def get_prompt(review_pr):
    return f"""
You are an experienced senior software engineer reviewing a GitHub pull request. Below is the PR metadata and code diffs.

  ✍️ Your task is to generate a **structured, clear, concise, and friendly** PR review comment. Use the following format:

  ---

  ### 📝 Summary
   Briefly explain what this PR does and the nature of the changes. Use a **numbered list**.

  ### ⚠️ Potential Issues
   Identify possible bugs, breaking changes, missing edge cases, or best practice violations. Use a **numbered list**.

  ### 🚀 Potential Optimizations
   Suggest improvements to performance, readability, or simplicity. Use a **numbered list**.

  ### 💡 Suggestions & Comments
   Optional: Praise good practices, suggest tests, or style improvements. Use a **numbered list**.

  ---

  ✅ **Tone**: Friendly and to the point. Use emojis where appropriate.
  ⛔ **Avoid**: Repeating raw code or including anything outside the review comment itself.  
    **Note**: Some files may be truncated here for tokens optimisation but are complete in the actual PR.
    **Important**: The output will be posted directly as a GitHub PR comment. Don’t include anything else.
  ---

  ###  PR Metadata:
  - PR Number: {review_pr["pr_number"]}
  - Title: {review_pr["title"]}
  - Description: {review_pr["body"]}
  - Target Branch: {review_pr["target_branch"]}

  ### Changed Files and Diffs:
  {format_changed_files(review_pr['files'], int(review_pr["max_input_tokens"] * TOKEN_MULTIPLIER))}
  """

def call_model(prompt, model_key, max_output_tokens=512):
    """
    Send the prompt to OpenRouter via the OpenAI SDK.
    """
    resp = openai_client.chat.completions.create(
        model=model_key,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.5,
        max_tokens=max_output_tokens,
        top_p=1.0,
    )
    return resp.choices[0].message.content

def add_model_data(pr):
    """
    Choose an OpenRouter model based on the user’s request:
      - Claude if requested (via OpenRouter’s Anthropic integration)
      - Otherwise an OpenAI model
    """
    req = pr.get("model", "").lower()
    if req.startswith("claude"):
        # OpenRouter’s name for Claude 3.5
        pr["model_key"] = "anthropic/claude-3.5-sonnet"
        pr["max_input_tokens"] = 10000
    else:
        # fallback to WaveAssist’s default OpenAI model
        pr["model_key"] = "gpt-4o-mini"
        pr["max_input_tokens"] = 20000

    return pr

# Main loop
prs = waveassist.fetch_data("pull_requests")
for pr in prs:
    try:
        pr = add_model_data(pr)
        prompt = get_prompt(pr)
        pr["comment"] = call_model(prompt, pr["model_key"])
        pr.update(comment_generated=True, comment_posted=False)
        print(f"✅ PR #{pr['pr_number']} reviewed.")
    except Exception as e:
        print(f"❌ PR #{pr.get('pr_number')} failed: {e}")
        pr.update(comment="", comment_generated=False, comment_posted=False)

waveassist.store_data("pull_requests", prs)
print("✅ All done.")
