# راه‌بان SSH · Rahban SSH

وب‌سایت رسمی / Official website: [rahbanssh.github.io/rahbanssh](https://rahbanssh.github.io/rahbanssh/)

## راهنمای فارسی

راه‌بان یک پنل فارسی و واکنش‌گرا برای ساخت و مدیریت حساب‌های SSH Tunnel است. حساب‌های مشتریان داخل یک کانتینر Docker ایزوله ساخته می‌شوند و به کاربران سیستم‌عامل اصلی VPS دسترسی ندارند.

### ساختار پورت‌ها

- `22/tcp`: اتصال مشتریان و کانفیگ‌های SSH Tunnel
- `2222/tcp`: مدیریت خود VPS با کاربر `root` یا مدیر سرور
- `80/tcp` و `443/tcp`: پنل وب و دریافت خودکار SSL
- `127.0.0.1:19080`: دسترسی اضطراری محلی به پنل

پورت ۲۲ ممکن است در بعضی شبکه‌ها در دسترس‌تر باشد، ولی هیچ تضمینی برای عبور از محدودیت‌های شبکه یا فیلترینگ وجود ندارد. راه‌بان پورت SSH مدیریتی VPS را بدون تغییر فایل اصلی `sshd_config` به سرویس اختصاصی پورت ۲۲۲۲ منتقل می‌کند و پورت ۲۲ را به کانتینر مشتریان می‌دهد.

> [!CAUTION]
> پس از نصب، ورود مدیریتی قبلی روی پورت ۲۲ دیگر برای VPS اصلی نیست. نصب‌کننده فرمان کامل جدید را داخل یک کادر قرمز چاپ و در فایل `install-summary.txt` ذخیره می‌کند. آن فرمان را نگه دارید و تا زمانی که در ترمینال دوم کار نکرده، اتصال فعلی را نبندید:
>
> ```bash
> ssh -p 2222 root@SERVER_IP
> ```

### قبل از نصب — بسیار مهم

1. در فایروال پنل شرکت VPS، پورت‌های TCP زیر را باز کنید: `22`، `2222`، `80` و `443`.
2. مطمئن شوید به کنسول اضطراری/VNC شرکت ارائه‌دهنده VPS دسترسی دارید.
3. نصب را در یک نشست SSH باز اجرا کنید و تا آزمایش اتصال دوم، نشست فعلی را نبندید.
4. بهتر است نصب ابتدا روی یک VPS تازه انجام شود.

### نصب یک‌خطی

روی Ubuntu، Debian، Fedora یا سیستم مبتنی بر `apt`/`dnf` با دسترسی root اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/rahbanssh/rahbanssh/main/install.sh | sudo env RAHBAN_MOVE_HOST_SSH=1 bash
```

نصب‌کننده به‌صورت خودکار:

- IPv4 عمومی سرور را تشخیص می‌دهد؛
- آدرسی شبیه `ssh-panel-203-0-113-10.sslip.io` می‌سازد؛
- Docker را در صورت نیاز نصب می‌کند؛
- سرویس مدیریت VPS را روی پورت ۲۲۲۲ راه‌اندازی و آزمایش محلی می‌کند؛
- SSH اصلی سیستم را متوقف می‌کند و پورت ۲۲ را به کانتینر مشتریان می‌دهد؛
- Traefik و گواهی رایگان Let's Encrypt را راه‌اندازی می‌کند؛
- دیتابیس خالی، کلیدهای SSH و رمز تصادفی مدیر را می‌سازد؛
- لینک پنل، نام کاربری، رمز مدیر و هر دو پورت SSH را چاپ می‌کند.
- فرمان کامل اتصال بعدی به VPS را داخل یک کادر قرمز و واضح چاپ می‌کند.

اطلاعات نصب فقط برای root در این فایل نیز ذخیره می‌شود:

```bash
sudo cat /opt/ssh-vpn-panel/install-summary.txt
```

### آزمایش ضروری پس از نصب

نشست فعلی SSH را نبندید. از یک ترمینال دوم اتصال مدیریت را آزمایش کنید:

```bash
ssh -p 2222 root@SERVER_IP
```

مشتری ساخته‌شده در پنل از این مسیر وصل می‌شود:

```bash
ssh -p 22 CUSTOMER_USERNAME@SERVER_IP
```

کانفیگ آماده NPV Tunnel نیز به‌طور خودکار با IP سرور، پورت `22`، نام کاربری و رمز همان مشتری ساخته می‌شود.

### بازگردانی

برای توقف پنل، حفظ اطلاعات و بازگرداندن SSH مدیریتی قبلی:

```bash
sudo /opt/ssh-vpn-panel/rollback.sh
```

توجه: پس از rollback، اتصال مدیریت دوباره طبق تنظیمات قبلی سرور—معمولاً پورت ۲۲—خواهد بود. هنگام اجرای rollback نیز کنسول اضطراری در دسترس باشد.

### امکانات اصلی

- نقش مالک، نماینده و زیرنماینده
- اختصاص اعتبار حجمی و تاریخ انقضا به نمایندگان
- محدودیت حجم، زمان و ۱ تا ۱۰۰ اتصال هم‌زمان
- نمایش مصرف، کاربر آنلاین، آخرین IP و تاریخ شمسی
- ساخت، ویرایش و حذف پلن‌های فروش
- دکمه‌های افزایش سریع زمان، حجم و تعداد اتصال
- کپی IP، پورت، نام کاربری، رمز و کانفیگ `npvt-ssh://`
- ربات اختیاری تلگرام برای فروش، تست، سفارش و تغییر رمز
- گزارش رویدادها و پشتیبان‌گیری محافظت‌شده

هیچ بک‌دور، پورسانت اجباری، ارسال اطلاعات، حساب سازنده یا دسترسی مخفی در پروژه وجود ندارد.

نظرات، پیشنهادها و بازخورد: [rahbanssh@gmail.com](mailto:rahbanssh@gmail.com)

---

## English guide

Rahban SSH is a Persian-first, responsive panel for managing SSH Tunnel accounts. Customer Linux users exist only inside an isolated Docker container and do not receive access to the VPS host.

### Port layout

- `22/tcp`: customer SSH Tunnel connections
- `2222/tcp`: VPS administration (`root` or another host administrator)
- `80/tcp` and `443/tcp`: web panel and automatic TLS
- `127.0.0.1:19080`: loopback-only emergency panel endpoint

Port 22 may be reachable on networks that restrict uncommon ports, but this is not guaranteed. Rahban creates a dedicated management SSH service on port 2222, stops the original host listener, and then publishes the isolated customer container on port 22.

> [!CAUTION]
> After installation, the old port-22 login no longer reaches the VPS host. The installer prints the complete replacement command in a prominent red terminal box and saves it in `install-summary.txt`. Keep it, and do not close the current session until this works in a second terminal:
>
> ```bash
> ssh -p 2222 root@SERVER_IP
> ```

### Critical prerequisites

1. Allow inbound TCP `22`, `2222`, `80`, and `443` in the VPS provider firewall.
2. Confirm that the provider's emergency/VNC console works.
3. Keep the current SSH session open until a second management login succeeds.
4. Prefer a fresh VPS for the first installation.

### One-line installation

Run as root on a public `apt`- or `dnf`-based VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/rahbanssh/rahbanssh/main/install.sh | sudo env RAHBAN_MOVE_HOST_SSH=1 bash
```

After installation, test management access from a second terminal before closing the first:

```bash
ssh -p 2222 root@SERVER_IP
```

Customer accounts created by the panel connect to:

```bash
ssh -p 22 CUSTOMER_USERNAME@SERVER_IP
```

The installer detects the public IPv4 address, creates an `sslip.io` hostname, installs Docker if needed, obtains a Let's Encrypt certificate, starts the panel and isolated SSH service, creates a zero-state SQLite database and random secrets, and prints the panel URL and credentials.

It also prints and saves the exact future management command, using the detected sudo user when applicable—for example `ssh -p 2222 ubuntu@SERVER_IP` instead of assuming root.

The root-only installation summary is available at:

```bash
sudo cat /opt/ssh-vpn-panel/install-summary.txt
```

Stop Rahban, preserve its database, and restore the previous host SSH service with:

```bash
sudo /opt/ssh-vpn-panel/rollback.sh
```

Main features include owner/reseller/child-reseller roles, delegated traffic credit, quota and expiry enforcement, concurrent-connection limits, Jalali dates, editable sales plans, live usage, copyable SSH/NPV configurations, optional Telegram sales bots, audit logs, and protected backups.

There is no commission, backdoor, credential reporting, creator account, or hidden remote-access mechanism.

Feedback and suggestions: [rahbanssh@gmail.com](mailto:rahbanssh@gmail.com)

See [DEPLOYMENT.md](DEPLOYMENT.md) and [SECURITY.md](SECURITY.md) before production use. Licensed under the [MIT License](LICENSE).
