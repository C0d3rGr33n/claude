"""Train a byte-level transformer on a text file: python train.py input.txt"""
import sys

import torch

from model import Config, Transformer


def main(path, steps=2000, batch_size=32, lr=3e-4):
    device = "cuda" if torch.cuda.is_available() else "cpu"
    data = torch.tensor(list(open(path, "rb").read()), dtype=torch.long)
    cfg = Config()
    model = Transformer(cfg).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr)
    print(f"{sum(p.numel() for p in model.parameters()) / 1e6:.2f}M params on {device}")

    for step in range(steps):
        ix = torch.randint(len(data) - cfg.max_len - 1, (batch_size,))
        x = torch.stack([data[i:i + cfg.max_len] for i in ix]).to(device)
        y = torch.stack([data[i + 1:i + cfg.max_len + 1] for i in ix]).to(device)
        _, loss = model(x, y)
        opt.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        if step % 100 == 0:
            print(f"step {step}: loss {loss.item():.3f}")

    model.eval()
    out = model.generate(torch.zeros((1, 1), dtype=torch.long, device=device), 300, top_k=50)
    print(bytes(out[0].tolist()).decode(errors="replace"))
    torch.save(model.state_dict(), "transformer.pt")


if __name__ == "__main__":
    main(sys.argv[1])
