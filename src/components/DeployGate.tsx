import { useState } from "react";
import { Lock, Rocket, CheckCircle } from "lucide-react";

interface Props {
  deployable: boolean;
  failCount: number;
}

export function DeployGate({ deployable, failCount }: Props) {
  const [approved, setApproved] = useState(false);

  if (approved) {
    return (
      <div className="flex flex-col items-center gap-2 p-6 bg-green-50 border-2 border-green-400 rounded-2xl">
        <CheckCircle size={40} className="text-green-500" />
        <p className="text-xl font-bold text-green-700">Deployment Approved ✓</p>
        <p className="text-sm text-green-600">모든 보안 규칙을 통과했습니다. 안심하고 배포하세요!</p>
      </div>
    );
  }

  if (!deployable) {
    return (
      <div className="flex flex-col items-center gap-2 p-6 bg-gray-50 border-2 border-gray-300 rounded-2xl">
        <Lock size={32} className="text-gray-400" />
        <p className="text-lg font-bold text-gray-500">배포 차단됨</p>
        <p className="text-sm text-gray-400">보안 위반 {failCount}건을 먼저 해결하세요</p>
        <button disabled className="mt-2 w-full bg-gray-300 text-gray-500 font-semibold py-2 rounded-xl cursor-not-allowed">
          배포 불가
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-2 p-6 bg-green-50 border-2 border-green-300 rounded-2xl">
      <Rocket size={32} className="text-green-500" />
      <p className="text-lg font-bold text-green-700">모든 보안 규칙 통과!</p>
      <button
        onClick={() => setApproved(true)}
        className="mt-2 w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-xl transition-colors text-lg"
      >
        🚀 배포 승인
      </button>
    </div>
  );
}
