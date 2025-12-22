+++
title = 'Gemastik 2022 - Fast Miner'
date = '2022-10-29T00:00:00+07:00'
tags = ['ctf-writeup', 'editorial', 'web', 'crypto']
draft = false
+++

Ide awal dari soal ini sederhana sebenernya buat _aware_ orang tentang Bitcoin block hash. Bitcoin block hash ini punya satu karakteristik dimana hasil double hash (SHA-256) dari block header harus memiliki beberapa bit nol di belakangnya sebagai bentuk _Proof-of-Work_. Ide ini sebenernya lebih cocok untuk jadi soal misc-cryptography, _but here we are_ :p

Ide penggunaan bitcoin block hash ini sudah ada di beberapa CTF sebelumnya, i.e.

- [Bit Flip 3 - Dragon CTF 2020](https://ctftime.org/task/14014)
- [kv - HITB SECCONF CTF 2022](https://github.com/HITB-CyberWeek/hitbsecconf-ctf-2022/tree/main/writeups/kv)

## Ringkasan Soal

> source code bisa diakses di [https://gist.github.com/circleous/a97be308540c9163592a540750456589#file-main-py](https://gist.github.com/circleous/a97be308540c9163592a540750456589#file-main-py)

- `GET /` (mulai session baru untuk dapetin UID)
- `GET /notes?title=...` (cari notes berdasarkan title)
- `POST /notes` `title=...&content=....` (buat notes baru)

Skema penyimpanan notes menggunakan plain dictionary dimana untuk key-nya menggunakan 8 trailing bytes hasil dari SHA256(UID + title). Jadi untuk dapetin flagnya cukup _straightforward_ dengan _**cukup**_ cari hash dengan 8 trailing zero bytes karena sudah ada flag pada key 00…000 dimana Bitcoin block hash sudah lebih dari mencukupi untuk kebutuhan tersebut.

## Solve

Bitcoin chain data itu besar, jadi ga perlu download seluruh datanya. Cukup pakai block explorer api dan simpan beberapa hash dari block data yang bisa digunakan untuk tahap selanjutnya,

```py
def get_block_data(num=25) -> Dict[bytes, bytes]:
    latest_block = requests.get("https://blockchain.info/q/latesthash").text

    cur_block = latest_block
    res = {}

    for _ in range(num):
        resp = requests.get(f"https://blockchain.info/rawblock/{cur_block}",
                            params={"format": "hex"})
        block_data = resp.text
        header = bytes.fromhex(block_data[:160])

        h = sha256(header)
        hash = h.digest()

		# store data
        res[hash[:2]] = hash[2:]

        # reverse the byte order
        prev_block = header[35:3:-1].hex()

        # change cur_block to prev_block for the next iteration
        cur_block = prev_block

    return res

def main():
    block = get_block_data(12)
...
```

karena block data yang di dapat tidak banyak perlu sedikit brute untuk mendapatkan UID yang cocok lalu baru bisa dapat flagnya.

```py
def get_uid() -> Tuple[str, bytes]:
    resp = requests.get("http://localhost:8000")
    uid = bytes.fromhex(resp.text.split()[-1][:4])

    return resp.cookies.get("sessionId"), uid

def main():
	...
    while True:
        sessionId, uid = get_uid()
        title = block.get(uid)
        if title is not None:
            break

    assert sha256(uid + title).hexdigest().endswith("0000000000000000")

    resp = requests.get("http://localhost:8000/notes",
                        cookies={"sessionId": sessionId},
                        params={"title": title})
    print(resp.text) # flag
```

## The Pitfall and Unreleased Part of the Challenge

```py
notes: Dict[str, str] = {
    "00000000": os.environ.get("FLAG", "FLAG{test_flag}"),
}
```

Jadi 8 trailing bytes ini bukan tanpa sebab karena eksekusi awal dari ide soal ini memakai dotnet core dimana UID tidak diberikan dan perlu di overwrite terlebih dahulu dengan menggunakan UAF di stack allocation, tapi karena sampai beberapa jam sebelum lomba dimulai remote exploit belum bisa dan gagal terus, akhirnya saya speedrun untuk rewrite ke python saja dan lupa menaikkan difficulty dari PoW xD.

---

solver dan soal bisa diakses di [https://gist.github.com/circleous/a97be308540c9163592a540750456589](https://gist.github.com/circleous/a97be308540c9163592a540750456589)