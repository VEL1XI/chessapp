Elisa Bayu Hendra /233401015
Yohanes Emmanuel Putra Sutanto /233401017



♟️ Chess Multiplayer
Aplikasi catur multiplayer real-time yang dibangun menggunakan Go (Golang) untuk backend dan HTML/JavaScript untuk frontend. Aplikasi ini memungkinkan dua pemain untuk bermain catur dalam lobby yang berbeda dengan fitur otentikasi, manajemen profil, dan statistik pertandingan.

✨ Fitur Utama
Sistem Otentikasi: Pendaftaran (Register) dan Masuk (Login) pengguna yang aman menggunakan enkripsi bcrypt.

Catur Multiplayer Real-time: Permainan catur dua pemain yang beroperasi melalui WebSocket.

Manajemen Lobby: Pemain dapat bergabung dengan salah satu dari 8 lobby yang tersedia secara default.

Pembaruan Profil: Pengguna dapat memperbarui username dan mengunggah foto profil (profile picture).

Statistik Pemain: Melacak dan menampilkan Total Kemenangan, Kekalahan, Seri, dan Total Pertandingan.

Mekanisme Permainan Lengkap: Mendukung langkah catur standar, promosi pion, penentuan status (Skak/Check), Skakmat (Checkmate), dan Seri (Draw).

Fitur Rematch: Memungkinkan pemain untuk segera memulai pertandingan ulang dengan pertukaran warna bidak.

💻 Teknologi yang Digunakan
Proyek ini terbagi menjadi backend (API dan WebSocket) dan frontend (antarmuka pengguna).

Backend (Go)
Bahasa Pemrograman: Go (Golang) versi 1.25.1

Web Framework/Router: github.com/gorilla/mux

WebSocket: github.com/gorilla/websocket

Database: SQLite (modernc.org/sqlite)

Skema tabel: users (menyimpan data pengguna) dan games (menyimpan riwayat pertandingan).

Keamanan: golang.org/x/crypto/bcrypt untuk hashing kata sandi.

Frontend (HTML/JS)
Teknologi Dasar: HTML5, CSS3, JavaScript (ES6+)

Papan Catur: chessboard.js

Logika Catur: chess.js

Utilities: JQuery

⚙️ Persyaratan Sistem
Untuk menjalankan aplikasi ini secara lokal, Anda memerlukan:

Go (Golang) versi 1.25.1 atau yang lebih baru.

Akses ke Terminal/Command Prompt.

