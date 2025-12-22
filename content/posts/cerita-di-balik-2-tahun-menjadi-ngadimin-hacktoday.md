+++
title = '2 Tahun Menjadi Ngadimin HackToday'
date = '2019-08-25T00:00:00+07:00'
tags = ['rant']
draft = false
+++

Ini akan jadi beberapa seri _writeup_ untuk HackToday dan untuk bagian pertama, tulisan ini tidak berfokus pada editorial dari saya sebagai problem setter, tapi lebih ke sisi saya menjadi _ngadimin_, hehe.

Flash back ke 2018, tahun pertama jadi _ngadimin_, masa menjelang akhir-akhir tahun pertama saya kuliah di IPB, saya baru mengenal CTF di kalangan komunitas Indonesia saat itu dan langsung untuk menjadi problem setter acara ini (HackToday). Panik? _Sangad_. Jangankan untuk tahu docker dan dengan segala istilah _container_\-blah, saya sendiri baru mulai _terjerumus_ ke dunia CTF awal tahun ajaran kuliah.

Saat itu, kami memiliki beberapa orang problem setter, tapi bagian "_sysadmin_" lebih terfokus pada saya dan bang Alfan. "_sysadmin_", dengan tanda kutip, ya.. mau gimana lagi? docker saja tidak tahu, mana mungkin saya paham cara _scaling_ dan lainnya. Kami berdua masih mengandalkan _setup_ dari tahun 2017, tapi bedanya, tidak ada yang tahu cara untuk membuat segalanya menjadi lebih efisien. Kurang lebih ini struktur dari setiap challenge yang perlu di _deploy_ ke server,

    .
    ├── Dockerfile
    ├── challenge
    └── flag

wait… gak ada compose file? yep, kalian tidak salah lihat. Kami pun tidak tahu bagaimana caranya memakai compose file. Ini adalah kasus kecil dimana problem kategori `pwn` yang hanya memerlukan bare minimal linux dengan glibc untuk binary dapat berjalan. Contoh bisa lihat di bawah, diambil dari soal `faile`, `HackToday 2017`.

Terus gimana yang `web`? Ini lebih ribet lagi karena perlu mengamankan beberapa set permission dengan benar, setup db dan cgi (php-fpm untuk nginx), dsb. Kalau dibandingkan, compose file jauh lebih mudah untuk setup yang seperti ini dan mengikuti filosofi docker sendiri, _single process per container_. Kemungkinan error-nya memang _gede_, tapi tetap melakukan ini karena tidak punya pilihan lain. _"Let it run on foreground, and keep our fingers crossed"_. Ternyata, error masih tetep ada. Gak kurang-kurang, kejadiannya di soal `web` saat lomba sedang berlangsung sehingga soal perlu di _takedown_ beberapa jam untuk maintenis, wkwkw. Sebenernya, ga cuma di web sih, kalau ingat, kami di awal salah memasukkan beberapa binary dan web pada service yang berjalan sehingga waktu perlombaan perlu ditambah dua jam. Intinya, sangat _prone to error_.

Di sisi server, karena kami pun tidak ada yang paham masalah hardware di server, kami hanya menghamburkan uang dengan membeli 2 server yang "lumayan" _and again, keep our fingers crossed_. Alhasil, CTFd yang kurang responsif walau tak separah kualifikasi compfest beberapa minggu lalu.

![take my money](https://i.imgur.com/eFfmdb3.jpg)_Shut up and Take my money!_

Moral of the story, jangan diikuti gan.

Pada tahun kedua ini, walaupun kelihatannya _fine-fine_ aja, sebenarnya tidak banyak yang berubah dari tahun pertama selain sudah mulai mengimplementasikan `docker-compose` dan load balancer di beberapa _service_ penting. Tidak banyak berubah karena dari sisi keuangan sendiri gak berbeda jauh dari tahun lalu (hanya berkurang 50%), seharusnya bisa jauh lebih efisien dengan [GKE](https://cloud.google.com/kubernetes-engine/), tapi dengan human resource yang hanya satu orang di bagian sysadmin, saya sendiri, belajar hal baru sambil menyiapkan soal dan berbagai drama internal, lebih baik saya tetap memakai model server monolitik. 2 server untuk menjalakan service dan 1 server pribadi saya untuk load balancer. Detail untuk setup sendiri akan saya bahas pada _post_ selanjustnya, walaupun saya sendiri tidak menganjurkan untuk mengikuti setup ini yang lumayan _costly_.

Load balancer soal yang digunakan adalah nginx. CTFd di-_scale_ menjadi 4 dari awal dengan load balancer nginx pada main server. Dari semua "_dongeng_" ini, cloudflare juga lumayan bagus karena kami sempat mengalami downtime saat akses `/challenges` dan `/scoreboard` pada menit-menit awal, namun setelah beberapa saat kemudian website kembali stabil dengan kondisi bandwith mulai masuk ke cloudflare cached bandwith. Notable juga untuk tools docker-compose karena untuk one man team di sysadmin, hampir semua lebih _do-able_ untuk otomasi setup dan _maintenance_.

Pada Final, kami hampir tidak tidur 36 jam karena dari H-1 kami belum melakukan deployment dan tests sama sekali. Hal ini pun berlanjut sampai final berlangsung. Dasar mahasiswa, harus selalu sistem kebut semalam :v. Dampaknya lumayan gan, 3 soal web gak bisa ke deploy dan beberapa soal yang dapat mengeluarkan banyak pilihan flag.

_Closing thougt_, semua ini lebih "_worth the time and money_" karena memang niatnya untuk berbagi ilmu dan self improvement karena berusaha untuk menjadi _ngadimin_ yang layak walaupun ga kesampaian juga :v. Terimakasih buat peserta yang sudah mau dijadikan sebagai bahan percobaan kami sebagai "_sysadmin_". #enjoyaman

![pamit](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRoMrBJac-HniQMUazvAWpynl-YwQo1ZGSabj-mjjuck3sO0FFHig)_Saya pamit :”_