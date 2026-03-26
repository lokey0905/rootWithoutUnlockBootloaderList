# 近期被利用之「免解鎖 Bootloader 取得 Root」漏洞列表

> 用途：資安研究、風險追蹤與防護評估。
> 
> 注意：請勿用於未經授權的測試或攻擊行為。

---

# Xiaomi/Redmi/POCO
## 受影響裝置列表

| codename | 手機型號名稱 | 平台 | Android 版本 | 安全性修補日期 | 漏洞名稱 / CVE | 狀態 |
| --- | --- | --- | --- | --- | --- | --- |
| cupid     | Xiaomi 12         | Snapdragon 8 Gen 1    | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| zeus      | Xiaomi 12 Pro     | Snapdragon 8 Gen 1    | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| mayfly    | Xiaomi 12S        | Snapdragon 8+ Gen 1   | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| unicorn   | Xiaomi 12S Pro    | Snapdragon 8+ Gen 1   | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| thor      | Xiaomi 12S Ultra  | Snapdragon 8+ Gen 1   | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| fuxi      | Xiaomi 13         | Snapdragon 8 Gen 2    | Android 13 | N/A | ABL Cmdline Injection | 未測試 |
| nuwa      | Xiaomi 13 Pro     | Snapdragon 8 Gen 2    | Android 13 | N/A | ABL Cmdline Injection | 未測試 |
| ishtar    | Xiaomi 13 Ultra   | Snapdragon 8 Gen 2    | Android 13 | N/A | ABL Cmdline Injection | 未測試 |
| houji     | Xiaomi 14         | Snapdragon 8 Gen 3    | Android 14 | N/A | ABL Cmdline Injection | 已測試 |
| shennong  | Xiaomi 14 Pro     | Snapdragon 8 Gen 3    | Android 14 | N/A | ABL Cmdline Injection | 未測試 |
| aurora    | Xiaomi 14 Ultra   | Snapdragon 8 Gen 3    | Android 14 | N/A | ABL Cmdline Injection | 未測試 |
| dada      | Xiaomi 15         | Snapdragon 8 Elite    | Android 15 | N/A | ABL Cmdline Injection | 未測試 |
| haotian   | Xiaomi 15 Pro     | Snapdragon 8 Elite    | Android 15 | N/A | ABL Cmdline Injection | 未測試 |
| xuanyuan  | Xiaomi 15 Ultra   | Snapdragon 8 Elite    | Android 15 | N/A | ABL Cmdline Injection | 未測試 |
| pudding   | Xiaomi 17         | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| pandora   | Xiaomi 17 Pro     | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| popsicle  | Xiaomi 17 Pro Max | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| nezha     | Xiaomi 17 Ultra   | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| marble    | Redmi Note 12 Turbo / POCO F5     | Snapdragon 7+ Gen 2   | Android 13 | N/A | CVE-2025-21479 | 未測試 |
| ingres    | Redmi K50 Gaming / POCO F4 GT     | Snapdragon 8 Gen 1    | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| diting    | Redmi K50 Ultra / Xiaomi 12T Pro  | Snapdragon 8+ Gen 1   | Android 12 | N/A | CVE-2025-21479 | 未測試 |
| mondrian  | Redmi K60 / POCO F5 Pro           | Snapdragon 8+ Gen 1   | Android 13 | N/A | CVE-2025-21479 | 未測試 |
| socrates  | Redmi K60 Pro                     | Snapdragon 8 Gen 2    | Android 13 | N/A | CVE-2025-21479 | 未測試 |
| vermeer   | Redmi K70 / POCO F6 Pro           | Snapdragon 8 Gen 2    | Android 14 | N/A | CVE-2025-21479 | 未測試 |
| manet     | Redmi K70 Pro                     | Snapdragon 8 Gen 3    | Android 14 | N/A | CVE-2025-21479 | 未測試 |
| zorn      | Redmi K80 / POCO F7 Pro           | Snapdragon 8 Gen 3    | Android 15 | N/A | CVE-2025-21479 | 未測試 |
| miro      | Redmi K80 Pro / POCO F7 Ultra     | Snapdragon 8 Elite    | Android 15 | N/A | ABL Cmdline Injection | 未測試 |
| annibale  | Redmi K90 / POCO F8 Pro           | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| myron     | Redmi K90 Pro Max / POCO F8 Ultra | Snapdragon 8 Elite Gen 5 | Android 16 | N/A | ABL Cmdline Injection | 未測試 |
| liuqin    | Xiaomi Pad 6 Pro           | Snapdragon 8+ Gen 1 | Android 13    | N/A | ABL Cmdline Injection | 未測試 |
| yudi      | Xiaomi Pad 6 Max 14        | Snapdragon 8+ Gen 1 | Android 13    | N/A | ABL Cmdline Injection | 未測試 |
| ruyi      | Xiaomi MIX Flip            | Snapdragon 8 Gen 3  | Android 14    | N/A | ABL Cmdline Injection | 未測試 |
| bixi      | Xiaomi MIX Flip 2          | Snapdragon 8 Elite  | Android 15    | N/A | ABL Cmdline Injection | 未測試 |
| babylon   | Xiaomi MIX Fold 3          | Snapdragon 8 Gen 2  | Android 13    | N/A | ABL Cmdline Injection | 未測試 |
| goku      | Xiaomi MIX Fold 4          | Snapdragon 8 Gen 3  | Android 14    | N/A | ABL Cmdline Injection | 未測試 |

## 漏洞利用說明
### 1. CVE-2025-21479（Qualcomm Adreno GPU micronode 記憶體破壞）
此漏洞出現在 Qualcomm Adreno GPU 的 micronode 指令處理流程中；公開描述指出，攻擊者可藉由特定指令序列觸發未授權命令執行與記憶體破壞。公開的 GitHub PoC 為：

- https://github.com/zhuowei/cheese

若漏洞可被成功鏈接到系統提權路徑，可能進一步取得臨時 Root 權限，但實際影響仍會受到 SoC、GPU 世代、韌體版本與修補狀態影響。

### 2. ABL Cmdline Injection（fastboot OEM / ABL 命令列注入漏洞鏈）
此類漏洞鏈的核心在於 Qualcomm ABL（Android Bootloader）對 `fastboot oem` 某些參數的驗證不完整，導致不受信任的輸入被帶入 kernel cmdline。公開討論中，研究者展示了可藉由 OEM 指令額外注入如 `androidboot.selinux=permissive` 之類的啟動參數，進而削弱開機後的強制安全限制。

Qualcomm 對應修補提交也直接將問題描述為：
`Fix propagation of untrusted input into kernel cmdline`

因此，這條鏈本身通常不是最終目的，而是作為後續提權、臨時 Root、甚至免解鎖 Bootloader 操作的前置條件之一。

> 註：
> - `CVE-2025-21479` 為已公開編號之 GPU 漏洞。
> - `ABL Cmdline Injection` 為整理用途的技術性名稱，用來統稱 fastboot OEM / ABL 參數驗證不完整、可導致 kernel cmdline 注入的漏洞鏈。

# OnePlus
