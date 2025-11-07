# Cách tích hợp iris-misp-pusher vào IRIS Docker

## Phương án 1: Cài đặt vào container đang chạy (Khuyến nghị cho development)

Sử dụng script `install_to_docker.sh`:

```bash
cd iris-misp-pusher
./install_to_docker.sh
sudo docker restart iriswebapp_app iriswebapp_worker
```

## Phương án 2: Tích hợp vào Dockerfile (Khuyến nghị cho production)

### Bước 1: Copy module vào thư mục IRIS source

Giả sử IRIS Web và IRIS MISP Pusher source code đều ở `home`:

```bash
cp -r ~/iris-misp-pusher ~/iris-web/iris-misp-pusher
```

### Bước 2: Sửa Dockerfile của IRIS

Thêm vào Dockerfile (sau phần COPY source):

```dockerfile
# Copy và cài đặt iris-misp-pusher module
COPY ./iris-misp-pusher /iriswebapp/iris-misp-pusher
RUN /opt/venv/bin/pip install /iriswebapp/iris-misp-pusher/
```

**Lưu ý:** Phải thêm vào cả 2 Dockerfiles nếu IRIS có riêng Dockerfile cho app và worker.

### Bước 3: Rebuild IRIS Docker image

```bash
cd ~/iris-web/
docker-compose down
docker-compose build
docker-compose up -d
```


## Sau khi cài đặt

1. Truy cập IRIS UI
2. Vào **Advanced > Modules**
3. Click **Add module**
4. Nhập: `iris_misp_pusher`
5. Configure:
   - MISP URL: `https://<your-misp-host>`
   - MISP API Key: `<your-key>`
   - Event IP ID: `1808`
   - Event Hash ID: `1810`
6. Enable module
7. Vào Case > Click chuột phải vào IOC > **Push IOCs to MISP**

## Phát triển và debug

Khi sửa code:

```bash
cd ~/iris-web/iris-misp-pusher
# Sửa code...

# Reinstall
./install_to_docker.sh
sudo docker restart iriswebapp_app iriswebapp_worker

# Xem logs
sudo docker logs -f iriswebapp_worker
```
