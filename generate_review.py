"""
WaveAssist Node: Generate AI-Powered PR Review Comments with Fallbacks

This node generates review comments for GitHub PRs using OpenAI or Anthropic,
depending on which API keys are available. If neither key is valid, it aborts.

Inputs:
- prs_to_review: list of PR dicts
- gitzoid_openai_key: optional OpenAI API key (placeholder if unset)
- gitzoid_anthropic_key: optional Anthropic API key (placeholder if unset)

Outputs:
- prs_to_review: same list, enriched with `comment`, `comment_generated`, `comment_posted`
"""


from openai import OpenAI
import anthropic
import waveassist

# Constants
TOKEN_MULTIPLIER = 2.5

# Initialize WaveAssist
waveassist.init()


def _init_client(fetch_key: str, client_cls):
    """
    Attempt to fetch an API key and initialize the client.
    Returns (client_instance or None, availability_flag).
    """
    api_key = waveassist.fetch_data(fetch_key)
    if api_key is None:
        print(f"⚠️ No API key found for {client_cls.__name__}.")
        return None, False
    try:
        return client_cls(api_key=api_key), True
    except Exception as e:
        print(f"❌ Failed to initialize {client_cls.__name__}: {e}")
    return None, False


# Set up clients
openai_client, openai_avail = _init_client("openai_key", OpenAI)
if openai_avail:
    print("✅ OpenAI client ready.")

anthropic_client, anthropic_avail = _init_client("anthropic_key", anthropic.Anthropic)
if anthropic_avail:
    print("✅ Anthropic client ready.")

if not (openai_avail or anthropic_avail):
    raise RuntimeError("❌ Neither OpenAI nor Anthropic key is available – nothing to do.")

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
  ????‍???? You are an experienced senior software engineer reviewing a GitHub pull request. Below is the PR metadata and code diffs.

  ✍️ Your task is to generate a **structured, clear, concise, and friendly** PR review comment. Use the following format:

  ---

  ### 📝 Summary
  ???? Briefly explain what this PR does and the nature of the changes. Use a **numbered list**.

  ### ⚠️ Potential Issues
  ???? Identify possible bugs, breaking changes, missing edge cases, or best practice violations. Use a **numbered list**.

  ### 🚀 Potential Optimizations
  ???? Suggest improvements to performance, readability, or simplicity. Use a **numbered list**.

  ### 💡 Suggestions & Comments
  ???? Optional: Praise good practices, suggest tests, or style improvements. Use a **numbered list**.

  ---

  ✅ **Tone**: Friendly and to the point. Use emojis where appropriate.
  ⛔ **Avoid**: Repeating raw code or including anything outside the review comment itself.  
  ???? **Important**: The output will be posted directly as a GitHub PR comment. Dont include anything else.

  ---

  ### ???? PR Metadata:
  - PR Number: {review_pr["pr_number"]}
  - Title: {review_pr["title"]}
  - Description: {review_pr["body"]}
  - Target Branch: {review_pr["target_branch"]}

  ### ????️ Changed Files and Diffs:
  {format_changed_files(review_pr['files'], int(review_pr["max_input_tokens"] * TOKEN_MULTIPLIER))}
  """


def call_openai(prompt, model_key):
    resp = openai_client.responses.create(
        model=model_key,
        input=[{"role": "user", "content": [{"type": "input_text", "text": prompt}]}],
        text={"format": {"type": "text"}},
        reasoning={}, tools=[],
        temperature=0.5, max_output_tokens=512, top_p=1, store=True,
    )
    return resp.output[0].content[0].text


def call_anthropic(prompt, model_key):
    msg = anthropic_client.messages.create(
        model=model_key,
        max_tokens=512, temperature=0.5,
        messages=[{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    )
    return msg.content[0].text


def add_model_data(pr):
    """
    Determine which client to use:
      - If Claude requested but Anthropic unavailable, fall back to OpenAI
      - If OpenAI requested but unavailable, fall back to Anthropic
    """
    req = pr.get("model", "gpt-4o-mini")
    use = None

    if req.lower().startswith("claude") and anthropic_avail:
        use = ("anthropic", "claude-3-5-haiku-20241022", 10000)
    elif req.lower().startswith("claude") and not anthropic_avail:
        print(f"⚠️ Claude requested but unavailable for PR #{pr['pr_number']} – using OpenAI.")
    if (not req.lower().startswith("claude") or use is None) and openai_avail:
        use = ("openai", "gpt-4o-mini", 20000)
    elif use is None:
        print(f"⚠️ OpenAI unavailable – using Anthropic for PR #{pr['pr_number']}.")

    pr.update({
        "client": use[0],
        "model_key": use[1],
        "max_input_tokens": use[2]
    })
    return pr


# Main loop
prs = waveassist.fetch_data("pull_requests")
for pr in prs:
    try:
        pr = add_model_data(pr)
        prompt = get_prompt(pr)
        if pr["client"] == "anthropic":
            pr["comment"] = call_anthropic(prompt, pr["model_key"])
        else:
            pr["comment"] = call_openai(prompt, pr["model_key"])
        pr.update(comment_generated=True, comment_posted=False)
        print(f"✅ PR #{pr['pr_number']} reviewed.")
    except Exception as e:
        print(f"❌ PR #{pr.get('pr_number')} failed: {e}")
        pr.update(comment="", comment_generated=False, comment_posted=False)

waveassist.store_data("pull_requests", prs)
print("✅ All done.")
