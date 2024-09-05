---
title: "Ngadimin dari HackToday 2019"
description: "Ringkasan data dari HackToday CTF 2019"
pubDate: "August 25 2019"
tags: ["rant"]
---

![logo](/img/hacktoday-logo.png)_codepwnda ini bukan nama baru CSI, bukan juga organisasi atau pun komunitas baru._

Tulisan ini adalah bagian kedua dari seri _writeup_ HackToday, masih membahas dari sisi _Ngadimin_ HackToday 2019.

# Kualifikasi

Sebelumnya, saya mau klarifikasi lebih dahulu xD. Akses platform kami memang stabil, tapi kalau dibandingkan dengan jumlah tim yang terdaftar pada compfest 12, sangat beda jauh. Iya, tim yang terdaftar kali ini hanya sekitar ~50 tim. Tidak heran, untuk server yang mungkin bisa mengakomodir ~500 orang dan realita hanya diakses oleh ~150 orang, bisa dikatakan, ini perbandingan yang kurang relevan xD.

## statistics

![logo](/img/hacktoday-stats.png)_top sekret unreleased challs_

52 team dengan terdaftar dengan 1 soal, _sanity check_, mencapai 100% solved percentage. Gak heran, karena ini termasuk free flag. ¯\\\_(ツ)\_/¯

![submission](/img/hacktoday-rw-submission.png)_597 wrong submission. :(_

Ada _597 wrong submission_ selama CTF berlangsung dan lebih dari 50% wrong submission berasal dari soal kategori Forensik. Ini cukup menyedihkan sih, mengingat kami dari probset sendiri lebih fokus kepada soal crypto, pwn, rev, dan web. sad.

![guess god](https://images-ext-1.discordapp.net/external/-D-TbFsk1aWQu9l5xgYlopUpc8GTrtHadXFRrilgQhA/https/pbs.twimg.com/media/D7uZZvsWsAEXHAm.png)_Sebenernya ini bukti nyata dari forensic - guess god, lol._

![cloudflare](/img/hacktoday-cloudflare.png)_cloudflare_

## the setup

**warn**, masih banyak [tutorial](https://medium.com/@iamalsaher/the-admin-side-of-evlzctf-2019-ccb77d45c74d) [diluar sana](https://www.youtube.com/watch?v=kUmaKvxdfvg) menggunakan cara yang lebih efisien.

Lanjutan penjelasan pada _post_ sebelumnya, setelah server masuk ke pemilihan platform. Pemilihan platform ini sebenernya agak sulit, tapi pada akhirnya CTFd masih tetap digunakan. Ke-“panik”-an ini berawal dari kompetisi lain seminggu sebelum HackToday dimulai mengalami downtime yang cukup lama, dan sebenernya udah menjadi _known issues_ di [CTFd #1012](https://github.com/CTFd/CTFd/issues/1012). Database server masih di satu server yang sama tapi berbeda dari instance docker CTFd (Saya ga pakai Google Cloud SQL atau service semacamnya). Ini supaya CTFd dapat di “scale” dengan mudah karena sebelum jalanin CTFd perlu set `DATABASE_URL` ke db server yang sudah dibuat sebelumnya dan SECRET*KEY dari file `.ctfd_secret_key` konstan untuk semua \_instance* CTFd yang akan dijalankan. Info lebih lanjut hubungi [+6221-9696-9293](https://github.com/CTFd/CTFd/wiki/Advanced-Deployment) (nvm, just click the link lol). Scaling ini perlu dibarengin sama load balancer, saya sendiri pakai nginx untuk setup load balancer, contoh konfigurasinya,

```nginx
    upstream ctfd {
        least_conn;
        server backend1:8000;
        server backend2:8001;
        server backend3:8002;
        server backend4:8003;
    }

    server {
        listen 50000;

        access_log /var/log/nginx/ctfd/access.log;
        error_log /var/log/nginx/ctfd/error.log;

        proxy_set_header HOST $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        location / {
            proxy_pass http://ctfd;
        }
    }
```

Advanced configuration bisa dilihat dari [dokumentasi nginx](http://nginx.org/en/docs/http/load_balancing.html) atau blog dari [digitalocean](https://www.digitalocean.com/community/tutorials/understanding-nginx-http-proxying-load-balancing-buffering-and-caching).

Untuk service soal-soal karena perlu lewat tcp, cloudflare perlu di set jadi DNS only.

![dns only](/img/hacktoday-cf-dns-only.png)_dns only, kalau masih ingat ini dari not.codepwnda.id_

jika perlu, scale juga soal-soal yang dirasa cukup unstable untuk masalah koneksi. btw, nginx juga bisa dipakai untuk [load balancer TCP/UDP](https://docs.nginx.com/nginx/admin-guide/load-balancer/tcp-udp-load-balancer/).

# Final

Para tim finalis bisa dilihat di instagram IT TODAY, [link](https://www.instagram.com/p/B1JZsmhg625/). btw, kalau kualitas soal mau dibandw ingkan dengan beberapa tahun kebelakang, ini sebenarnya final paling buruk dilihat dari banyaknya soal yang memerlukan bruteforce dan guessing. Meskipun dengan banyaknya soal yang “guessy” dan bruteforce, pada final kali ini kami tidak mempersiapkan banyak soal forensik dan misc dengan harapan mengurangi _wrong submisson_ seperti yang terjadi pada kualifikasi, tapi realitanya tidak. sad. ![sad af](/img/hacktoday-rw-submission-final.png) _sad af_

_The culprit?_ satu soal crypto, _ezhash_, dimana peserta harus mem-bruteforce correct flag, tapi siapa sangka,

```py
def hash(x):
    x ^= x >> 16
    x *= 0xd76aa478
    x &= 0xffffffff
    x ^= x >> 13
    x *= 0xe8c7b756
    x &= 0xffffffff
    x ^= x >> 14
    return x
```

hanya karena konstanta yang dipakai bukan bilangan prima, hash collision mudah banget dicapai.

![NO SYSTEM IS SAFE](/img/hacktoday-nosystemissafe.png)_thanks to siapa pun itu yang sudah membuat tamplate depes ini xD_

btw, saya juga membuat soal untuk nge-troll (foto di atas), dimana peserta memang harus benar-benar guess where the flag dimana ini seharusnya menjadi free flag for all, tapi sampai beberapa jam terakhir hanya memiliki sedikit solve. sad.

Overall setup keseluruhan tidak jauh berbeda dengan kualifikasi, yang berbeda hanya kami tidak menggunakan load balancer sama sekali.

## saya pamit?

Ini mungkin akan menjadi seri terakhir saya untuk menjadi bagian board of ngadimin HackToday mengingat tahun depan saya harus mulai Kuliah Kerja NangidNyata. sad.
