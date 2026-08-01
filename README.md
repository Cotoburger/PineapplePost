# 📦 Track24 Telegram Bot

A Telegram bot for tracking postal shipments using [track24.ru](https://track24.ru).  
Send a tracking number to the bot and it will monitor the shipment. You will be notified whenever new tracking events appear.

## ✨ Features

- Track any tracking number (5–28 characters) supported by track24.ru
- Display the last three events with date, status, location, and carrier
- Automatic updates every 1 hour via GitHub Actions
- Subscription state saved between runs (persisted in the repository)
- Cloudflare bypass using cloudscraper