import waveassist
from pydantic import BaseModel

# Constants
TOKEN_MULTIPLIER = 2.5
max_tokens = 1024
temperature = 0.5

waveassist.init(check_credits=True)

print("Processing AI Review Generation node")


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
            patch = f.get("patch", "")
            status = f.get("status", "modified")
            additions = f.get("additions", 0)
            deletions = f.get("deletions", 0)
            
            status_badge = f"[{status}]" if status != "modified" else ""
            stats = f"(+{additions}/-{deletions})" if additions or deletions else ""
            
            if not patch:
                block = f"{idx}. Filename: `{f['filename']}` {status_badge} {stats}\n*No diff available for this file.*"
            else:
                block = f"{idx}. Filename: `{f['filename']}` {status_badge} {stats}\n```\n{patch}\n```"

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


# Pydantic models for structured output
class PRReviewResult(BaseModel):
    """Model for full (first-time) PR review."""
    summary: list[str]
    potential_issues: list[str]
    potential_optimizations: list[str]
    suggestions: list[str]


class IncrementalReviewResult(BaseModel):
    """Model for incremental (follow-up) PR review after new commits."""
    changes_summary: list[str]
    addressed_issues: list[str]
    new_observations: list[str]


def get_full_review_prompt(review_pr, max_input_tokens=20000, additional_context=None):
    """Generate prompt for first-time full PR review."""
    formatted_files = format_changed_files(
        review_pr["files"], int(max_input_tokens * TOKEN_MULTIPLIER)
    )

    context_section = ""
    if additional_context and additional_context.strip():
        context_section = f"""
---
Additional context provided to help you with the review, just for reference, not necessary to use it, or only use relevant parts if needed:
##CONTEXT START##
{additional_context.strip()}
##CONTEXT END##
---
"""

    return f"""
You are an experienced senior software engineer reviewing a GitHub pull request. Provided is the PR metadata and code diffs.
Your task is to generate a structured, clear, concise, and friendly PR review comment.
For each section, provide the content as an array of strings representing the numbered list items. If a section has no items (e.g., optional Suggestions & Comments), use an empty array [].
Where:
- `summary`: Briefly explain in points what this PR does and the nature of the changes.  
- `potential_issues`: Identify possible bugs, breaking changes, missing edge cases, or best practice violations in point form.  
- `potential_optimizations`: Suggest improvements to performance, readability, or simplicity in point form.  
- `suggestions`: Optional: Praise good practices, suggest tests, or style improvements in point form.  

Note: Some files may be truncated here for tokens optimisation. That's ok. Post your analysis based on available context.

Guidelines:
- Tone: Friendly, short and to the point.
- Limit to 2-3 points per section, unless more are clearly needed.
- Do not repeat raw code or repeat the same thing in different points.  
    
{context_section}

*PRIMARY CONTENT TO REVIEW:*
---
PR Metadata:
  - PR Number: {review_pr.get("pr_number")}
  - Title: {review_pr.get("title")}
  - Description: {review_pr.get("body")}
---
Changed Files and Diffs:
{formatted_files}
---

Provide your review.
    """


def get_incremental_review_prompt(review_pr, previous_review=None, max_input_tokens=20000, additional_context=None):
    """Generate prompt for incremental review after new commits."""
    formatted_files = format_changed_files(
        review_pr["files"], int(max_input_tokens * TOKEN_MULTIPLIER)
    )

    context_section = ""
    if additional_context and additional_context.strip():
        context_section = f"""
---
Additional context:
{additional_context.strip()}
---
"""

    previous_review_section = ""
    if previous_review:
        previous_review_section = f"""
---
**Previous GitZoid Review (for reference):**
{previous_review}
---
"""

    # Safely extract SHA values, handling None or empty strings
    previous_sha_raw = review_pr.get("previous_sha") or ""
    current_sha_raw = review_pr.get("current_sha") or ""
    previous_sha = previous_sha_raw[:7] if previous_sha_raw else ""
    current_sha = current_sha_raw[:7] if current_sha_raw else ""

    return f"""
You are an experienced senior software engineer reviewing NEW COMMITS pushed to an existing GitHub pull request.
This is a FOLLOW-UP review - the PR was previously reviewed, and new code has been pushed.

Your task is to analyze ONLY the new changes (diff from commit {previous_sha} to {current_sha}) and provide:
1. `changes_summary`: What these new commits do - summarize the changes made.
2. `addressed_issues`: Which issues from the previous review (if any) have been addressed by these changes.
3. `new_observations`: Any NEW issues, concerns, or suggestions based on the new code (optional - use empty array if none).

{previous_review_section}

{context_section}

**NEW CHANGES TO REVIEW:**
---
PR Metadata:
  - PR Number: {review_pr.get("pr_number")}
  - Title: {review_pr.get("title")}
  - Description: {review_pr.get("body")}
  - Previous SHA: {previous_sha}
  - Current SHA: {current_sha}
---
New Changes (files modified since last review):
{formatted_files}
---

Guidelines:
- Focus ONLY on the new changes.
- Tone: Friendly, short and to the point.
- Limit to 2-3 points per section, unless more are clearly needed.
- Do not repeat raw code or repeat the same thing in different points.  
- If the new commits seem to address previous concerns, acknowledge that positively.
- For `new_observations`, only include if there are genuine new concerns.

Provide your incremental review.
"""


# Main code
prs = waveassist.fetch_data("pull_requests") or []
if prs:
    model_name = waveassist.fetch_data("model_name") or "anthropic/claude-haiku-4.5"
    additional_context = waveassist.fetch_data("additional_context") or ""
    
    for pr in prs:
        try:
            if pr.get("comment_generated", False):
                continue
            
            review_type = pr.get("review_type", "full")
            
            if review_type == "incremental":
                # Incremental review for new commits
                previous_review = pr.get("previous_review_text")
                prompt = get_incremental_review_prompt(
                    pr, 
                    previous_review=previous_review,
                    additional_context=additional_context
                )
                result = waveassist.call_llm(
                    model=model_name,
                    prompt=prompt,
                    response_model=IncrementalReviewResult,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                
                if not result:
                    raise Exception("❌ Incremental review not generated.")
                
                review_dict = result.model_dump(by_alias=True)
                pr.update(
                    review_dict=review_dict,
                    comment_generated=True,
                    comment_posted=False,
                    review_type="incremental"
                )
                print(f"✅ PR #{pr.get('pr_number')} incremental review generated.")
            else:
                # Full review for new PRs
                prompt = get_full_review_prompt(pr, additional_context=additional_context)
                result = waveassist.call_llm(
                    model=model_name,
                    prompt=prompt,
                    response_model=PRReviewResult,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )

                if not result:
                    raise Exception("❌ Review not generated.")

                review_dict = result.model_dump(by_alias=True)
                pr.update(
                    review_dict=review_dict,
                    comment_generated=True,
                    comment_posted=False,
                    review_type="full"
                )
                print(f"✅ PR #{pr.get('pr_number')} full review generated.")
                
        except Exception as e:
            print(f"❌ PR #{pr.get('pr_number')} failed: {e}")
            pr.update(review_dict={}, comment_generated=False, comment_posted=False)

    waveassist.store_data("pull_requests", prs)
    print("All PR reviews processed and stored.")
