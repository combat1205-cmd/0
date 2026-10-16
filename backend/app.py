
import json
import os
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

BASE = Path(__file__).resolve().parent
MODEL_PATH = Path(os.getenv("MODEL_PATH", str(BASE / "math_code_ai.pt")))
UPLOAD_DIR = BASE / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI(title="수학·코딩 AI")
device = "cuda" if torch.cuda.is_available() else "cpu"

model = None
stoi = {}
itos = {}
block_size = 128
load_error = None


class ChatRequest(BaseModel):
    question: str
    mode: str = "일반"


class MathCodeGPT(nn.Module):
    def __init__(self, vocab_size, block_size):
        super().__init__()
        n_embd = 128
        self.token_emb = nn.Embedding(vocab_size, n_embd)
        self.pos_emb = nn.Embedding(block_size, n_embd)

        layer = nn.TransformerEncoderLayer(
            d_model=n_embd,
            nhead=4,
            dim_feedforward=512,
            dropout=0.1,
            batch_first=True,
            activation="gelu",
        )
        self.blocks = nn.TransformerEncoder(layer, num_layers=2)
        self.norm = nn.LayerNorm(n_embd)
        self.head = nn.Linear(n_embd, vocab_size)

    def forward(self, idx):
        _, length = idx.shape
        positions = torch.arange(length, device=idx.device)
        x = self.token_emb(idx) + self.pos_emb(positions)

        mask = torch.triu(
            torch.ones(
                length, length,
                device=idx.device,
                dtype=torch.bool,
            ),
            diagonal=1,
        )
        x = self.blocks(x, mask=mask)
        return self.head(self.norm(x))

    @torch.no_grad()
    def generate(self, idx, max_new_tokens=220, temperature=0.5):
        self.eval()
        for _ in range(max_new_tokens):
            context = idx[:, -block_size:]
            logits = self(context)[:, -1, :]
            logits = logits / max(temperature, 0.1)
            probabilities = F.softmax(logits, dim=-1)
            next_id = torch.multinomial(probabilities, num_samples=1)
            idx = torch.cat([idx, next_id], dim=1)
        return idx


def load_model():
    global model, stoi, itos, block_size, load_error

    if not MODEL_PATH.exists():
        load_error = (
            f"모델 파일이 없습니다: {MODEL_PATH}. "
            "호환되는 학습 모델을 backend 폴더에 넣어 주세요."
        )
        return

    try:
        checkpoint = torch.load(
            MODEL_PATH,
            map_location=device,
            weights_only=False,
        )

        chars = checkpoint["chars"]
        block_size = int(checkpoint["block_size"])
        vocab_size = int(checkpoint["vocab_size"])

        stoi = {char: i for i, char in enumerate(chars)}
        itos = {i: char for i, char in enumerate(chars)}

        model = MathCodeGPT(vocab_size, block_size).to(device)
        model.load_state_dict(checkpoint["model"])
        model.eval()
        load_error = None

    except Exception as exc:
        model = None
        load_error = f"모델 로딩 오류: {exc}"


@app.on_event("startup")
def startup():
    load_model()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "device": device,
        "model_loaded": model is not None,
        "model_error": load_error,
    }


@app.post("/chat")
def chat(req: ChatRequest):
    if model is None:
        raise HTTPException(
            status_code=503,
            detail=load_error or "AI 모델이 준비되지 않았습니다.",
        )

    question = req.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="질문을 입력해 주세요.")

    hint = {
        "수학 풀이": "수학 문제를 단계별로 풀이해 줘. ",
        "Python 코딩": "Python 코드와 설명을 제공해 줘. ",
    }.get(req.mode, "")

    prompt = f"질문: {hint}{question}\n답변:"
    ids = [stoi[ch] for ch in prompt if ch in stoi]

    if not ids:
        return {"answer": "학습 데이터에 해당 문자가 없습니다."}

    idx = torch.tensor([ids], dtype=torch.long, device=device)
    generated = model.generate(idx)

    output = "".join(
        itos[int(token)] for token in generated[0].tolist()
    )
    original_prompt = "".join(itos[token] for token in ids)
    answer = output[len(original_prompt):]

    for stop in ("\n\n질문:", "\n질문:"):
        if stop in answer:
            answer = answer.split(stop, 1)[0]

    answer = answer.strip() or "답변을 만들지 못했습니다."
    return {"answer": answer, "mode": req.mode}


@app.post("/upload-data")
async def upload_data(file: UploadFile = File(...)):
    filename = Path(file.filename or "training.jsonl").name

    if not filename.lower().endswith((".jsonl", ".txt")):
        raise HTTPException(
            status_code=400,
            detail="JSONL 또는 TXT 파일만 올릴 수 있습니다.",
        )

    content = await file.read()

    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="파일은 10MB 이하여야 합니다.")

    if not content.strip():
        raise HTTPException(status_code=400, detail="빈 파일입니다.")

    if filename.lower().endswith(".jsonl"):
        try:
            for line_number, line in enumerate(
                content.decode("utf-8-sig").splitlines(), start=1
            ):
                if not line.strip():
                    continue
                item = json.loads(line)
                if "question" not in item or "answer" not in item:
                    raise ValueError(
                        f"{line_number}번째 줄에 question/answer가 없습니다."
                    )
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"JSONL 형식 오류: {exc}",
            )

    target = UPLOAD_DIR / filename
    target.write_bytes(content)

    return {
        "status": "uploaded",
        "filename": filename,
        "bytes": len(content),
        "message": "파일 저장 완료. 자동 재학습은 되지 않습니다.",
    }
