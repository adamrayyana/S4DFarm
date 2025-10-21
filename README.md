# S4DFarm

This is a fork of [DestructiveFarm](https://github.com/DestructiveVoice/DestructiveFarm), 
rewritten by the C4T BuT S4D team over the years.

## Running:
- Change the [./server/app/config.py](./server/app/config.py) file to your liking
    (don't forget to change the `SERVER_PASSWORD`).
- Change external_redis password in docker-compose.yml (of you're planning to use it).
- `docker compose up --build -d`
> Note:
>
> Kalo error pas ngepull alpine jalanin `docker pull redis:7.2.0-alpine`
- **GLHF**

## What To Do Before Compe

- Ganti config `SYSTEM_URL` dan `SYSTEM_TOKEN`
- Ganti regex jika diperlukan (defaultnya itu 32 character base64)

## What To Do During Compe

- Bikin exploit di `client/`
- Jalanin pake ./start_sploit.py <nama_exploit> 
> **!!!! IMPORTANT !!!!**
>
> Make sure nyalain flush=True kalo mau ngeprint ke stdout
> Kalo ga dinyalain ga kedetect 

Some screenshots:

![flags](resources/flags.png)

![teams](resources/teams.png)
