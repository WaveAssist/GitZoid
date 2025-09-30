from openai import OpenAI
import waveassist
import json
import re

# Constants
TOKEN_MULTIPLIER = 2.5

waveassist.init()

print("Processing AI Review Generation node")

# initialize OpenRouter client
openai_client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=waveassist.fetch_data("open_router_key"),
)


def extract_json(content):
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # try extracting from ```json ... ```
    start = content.find("```json")
    if start != -1:
        end = content.find("```", start + 6)
        if end != -1:
            try:
                return json.loads(content[start + 7 : end].strip())
            except json.JSONDecodeError:
                pass
    # fallback regex
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def format_changed_files(files, max_chars=25000):
    """Format file diffs into blocks, capping total length at max_chars."""
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        max_chars = 25000

    if not isinstance(files, (list, tuple)) or not files:
        return "No files changed."

    blocks, total = [], 0
    for idx, f in enumerate(files, 1):
        try:
            if "patch" not in f or f["patch"] is None:
                block = f"{idx}. Filename: `{f['filename']}`\n*No diff available for this file.*"
            else:
                block = f"{idx}. Filename: `{f['filename']}`\n```\n{f['patch']}\n```"

            length = len(block)
            blocks.append((length, block))
        except:
            pass

    blocks.sort(key=lambda x: x[0])
    included, remaining = [], []

    for length, block in blocks:
        if total + length <= max_chars:
            included.append(block)
            total += length
        else:
            remaining.append((length, block))

    if remaining:
        try:
            budget = (max_chars - total) + int(0.1 * max_chars)
            per_block = budget // len(remaining)
            for _, block in remaining:
                truncated = block.split("```", 1)[1][:per_block]
                included.append(
                    f"...\n```{truncated}\n... (file truncated for tokens optimisation, post your analysis based on available context.)\n```"
                )
        except:
            pass

    return "\n\n".join(included)


def get_prompt(review_pr, max_input_tokens=20000):
    formatted_files = format_changed_files(
        review_pr["files"], int(max_input_tokens * TOKEN_MULTIPLIER)
    )
    return f"""
You are an experienced senior software engineer reviewing a GitHub pull request. Provided is the PR metadata and code diffs.
Your task is to generate a structured, clear, concise, and friendly PR review comment in JSON format.
For each section, provide the content as an array of strings representing the numbered list items. If a section has no items (e.g., optional Suggestions & Comments), use an empty array [].
Where:
- `summary`: Briefly explain in points what this PR does and the nature of the changes.  
- `potential_issues`: Identify possible bugs, breaking changes, missing edge cases, or best practice violations in point form.  
- `potential_optimizations`: Suggest improvements to performance, readability, or simplicity in point form.  
- `suggestions`: Optional: Praise good practices, suggest tests, or style improvements in point form.  

Guidelines:
- Tone: Friendly and to the point.
- Avoid: Repeating raw code or repeating the same thing in different points.  
- Note: Some files may be truncated here for tokens optimisation. That's ok. Post your analysis based on available context.
    
---
PR Metadata:
  - PR Number: {review_pr.get("pr_number")}
  - Title: {review_pr.get("title")}
  - Description: {review_pr.get("body")}
---
Changed Files and Diffs:
{formatted_files}
---

Now, output strictly in the following JSON format (no additional text outside the JSON):
{{
    "summary": ["First item...", "Second item..."],
    "potential_issues": ["First item...", "Second item..."],
    "potential_optimizations": ["First item...", "Second item..."],
    "suggestions": ["First item...", "Second item..."]
}}

Return ONLY the JSON object. No markdown, commentary, or extra text—strict JSON for parsing.
Return JSON now:
    """


def execute_prompt(prompt, model_key, max_output_tokens=1024):
    """
    Send the prompt to OpenRouter via the OpenAI SDK.
    """
    try:
        resp = openai_client.chat.completions.create(
            model=model_key,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
            max_tokens=max_output_tokens,
        )
        return extract_json(resp.choices[0].message.content)
    except Exception as e:
        print(f"Error during model call: {e}")
        return {}


# Main code
prs = waveassist.fetch_data("pull_requests")
if prs:
    model_name = waveassist.fetch_data("model_name") or "x-ai/grok-code-fast-1"
    for pr in prs:
        try:
            if pr.get("comment_generated", False):
                continue
            prompt = get_prompt(pr)
            review_dict = execute_prompt(prompt, model_name)

            if not review_dict:
                raise Exception("❌ Review not generated.")

            pr.update(
                review_dict=review_dict, comment_generated=True, comment_posted=False
            )
            print(f"✅ PR #{pr['pr_number']} reviewed.")
        except Exception as e:
            print(f"❌ PR #{pr.get('pr_number')} failed: {e}")
            pr.update(review_dict={}, comment_generated=False, comment_posted=False)

    waveassist.store_data("pull_requests", prs)
    print("All PR reviews processed and stored.")
