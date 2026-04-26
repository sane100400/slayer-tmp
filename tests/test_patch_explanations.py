from __future__ import annotations

from backend.models import PatchResult as BackendPatchResult
from slayer.models import Violation
from slayer.patch_explanations import build_patch_explanations


def test_patch_explanations_are_backend_serializable():
    explanations = build_patch_explanations(
        [
            Violation(
                rule_id='NO_INSECURE_HASH',
                rule_name='NO_INSECURE_HASH',
                file='/tmp/app.py',
                line=12,
                code_snippet='hashlib.md5(password).hexdigest()',
                explanation='MD5 password hash',
            )
        ]
    )

    result = BackendPatchResult(
        original_code='old',
        patched_code='new',
        diff='@@',
        patch_explanations=[item.model_dump() for item in explanations],
        remaining_violations=[],
        deployable=True,
        ai_used='codex',
    )
    payload = result.model_dump()

    assert payload['patch_explanations'][0]['rule_name'] == 'NO_INSECURE_HASH'
    assert payload['patch_explanations'][0]['title'] == 'MD5/SHA1 해싱을 더 안전한 방식으로 바꿨어요'
    assert 'spec.md' in payload['patch_explanations'][0]['reference']
