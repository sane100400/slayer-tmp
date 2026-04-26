from __future__ import annotations

from backend.models import PatchResult as BackendPatchResult
from slayer.models import Violation
from slayer.rules import patch_explanation_for


def test_patch_explanations_are_backend_serializable():
    explanation = patch_explanation_for(
        Violation(
            rule_id='NO_INSECURE_HASH',
            rule_name='NO_INSECURE_HASH',
            file='/tmp/app.py',
            line=12,
            code_snippet='hashlib.md5(password).hexdigest()',
            explanation='MD5 password hash',
        )
    )

    result = BackendPatchResult(
        original_code='old',
        patched_code='new',
        diff='@@',
        patch_explanations=[explanation.model_dump()],
        remaining_violations=[],
        deployable=True,
        ai_used='codex',
    )
    payload = result.model_dump()

    assert payload['patch_explanations'][0]['rule_name'] == 'NO_INSECURE_HASH'
    assert payload['patch_explanations'][0]['title'] == '취약한 MD5/SHA1 해시를 교체했어요'
    assert 'spec.md' in payload['patch_explanations'][0]['reference']
