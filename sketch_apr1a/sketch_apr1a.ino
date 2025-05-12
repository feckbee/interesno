#include <M5StickCPlus2.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <Preferences.h>
#include <mbedtls/gcm.h>
#include <stdio.h>
#include <stdint.h> // Для uint8_t
#include <vector>  // Добавлено для работы с вектором
#include <map>     // Добавлено для AttackFilter
#include <Arduino.h>

Preferences preferences;

// Настройки
#define SCAN_INTERVAL 5000
#define MAX_DISPLAY_APS 5
#define MAX_PASSWORD_LEN 32
#define KEY_COLS 8
#define KEY_ROWS 4
#define DEAUTH_THRESHOLD 5 // Максимальное кол-во deauth пакетов
#define BEACON_FLOOD_THRESHOLD 50 // Пакетов/сек
int beaconCounter = 0;
unsigned long lastBeaconCheck = 0;
int deauthCounter = 0;
unsigned long lastDeauthReset = 0;
int calculateThreatLevel();

// Прототипы функций
void connectToSelectedNetwork();
void drawKeyboard();
void handleKeyboardInput();
void scanNetworks();  // Изменили название функции
void toggleDeauthDetection();
void toggleBeaconFloodDetection();
void clearStats();
void logError(const char* msg, int code);
void logAttack(const char* type, const uint8_t* attacker, const uint8_t* victim);
void checkBeaconFlood();
void mitigationActions(const String& attackType);
void analyzeTrafficPatterns();
void detectEvilTwin();
void drawStats();
void drawNetworkList();
void stopNetworkMonitoring();
void handleMonitoringMode();
void handleNormalMode();
void showDetailedStats();

// объявление структуры статистики
typedef struct {
    uint32_t rx_packets;  // Принятые пакеты
    uint32_t tx_packets;  // Переданные пакеты
    uint32_t rx_drop;     // Потерянные при приеме
    uint32_t tx_drop;     // Потерянные при передаче
} wifi_stats_t;
// Использование PSRAM если доступна
#if CONFIG_SPIRAM_SUPPORT
struct AccessPoint {
    String ssid;
    bool isEncrypted;
    int8_t rssi;
    uint8_t channel;
    uint8_t bssid[6];
} 
__attribute__((aligned(4))); // Выравнивание для DMA

#if !defined(UINT_MAX)
#define UINT_MAX 4294967295
#endif

std::vector<AccessPoint> aps;
#else
#define MAX_DISPLAY_APS 7
AccessPoint aps[MAX_DISPLAY_APS];
#endif
extern "C" {
esp_err_t esp_wifi_get_counters(wifi_interface_t ifx, wifi_stats_t *stats);
}

#if CONFIG_SECURE_BOOT_SUPPORTED
bool verifySystemIntegrity() {
    const uint8_t PUBLIC_KEY[64] = { /* Ваш публичный ключ */ };
    
    esp_image_sig_public_key_digests_t digests = {
        .keys = { PUBLIC_KEY },
        .num_keys = 1
    };
    
    return esp_secure_boot_verify_signature(0x0, 0x10000, &digests) == ESP_OK;
}
#else
bool verifySystemIntegrity() {
logError("Описание ошибки", 0);
    return false;
}
#endif

// Глобальные переменные
int apCount = 0;
bool attackDetected = false;
unsigned long lastScan = 0;
unsigned long lastPressA = 0;
int pressCountA = 0;
unsigned long lastPressB = 0;
int pressCountB = 0;
unsigned long lastPressTime = 0;
uint8_t pressCount = 0;
const uint32_t DOUBLE_PRESS_DELAY = 300; // 300ms между нажатиями
int selectedIndex = 0;
bool refreshList = true;
bool deauthEnabled = true;
bool beaconFloodEnabled = true;
bool inMenu = false;
//AttackFilter filter;
//int deauthCounter = 0;
int calculateThreatLevel();
uint8_t targetBSSID[6] = {0};

// Глобальные счетчики пакетов
volatile uint32_t rx_packets = 0;
volatile uint32_t tx_packets = 0;

String targetSSID = "";       // SSID целевой сети для мониторинга
bool isMonitoring = false;    // Флаг активного мониторинга

bool isSelectingPassword = false;

enum SecurityMode {
    BASIC,
    ENHANCED,
    PARANOID
};

SecurityMode currentMode = BASIC;
const uint8_t ENHANCED_FILTER_MASK = 0x80; // Фильтр Beacon фреймов

// Переменные клавиатуры
bool isKeyboardActive = false;
int keyboardPos = 0;
bool uppercase = false;
String passwordBuffer = "";
const char* charSets[3] = {
    "abcdefghijklmnopqrstuvwxyz012345",          // Набор 0
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ6789@$",          // Набор 1
};
// Реализация функции расчета угрозы
int calculateThreatLevel() {
    int threat = 0;
    
    // Взвешенные коэффициенты
    threat += min(deauthCounter * 2, 6);    // 1 deauth = 2 балла (макс 6)
    threat += min(beaconCounter / 10, 4);   // 10 beacon/сек = 1 балл (макс 4)
    
    return constrain(threat, 0, 10);        // Общий максимум 10
}

void logError(const char* msg, int code) {
    M5.Lcd.fillRect(0, M5.Lcd.height() - 20, M5.Lcd.width(), 20, TFT_RED);
    M5.Lcd.setTextColor(TFT_WHITE, TFT_RED);
    M5.Lcd.setCursor(2, M5.Lcd.height() - 18);
    M5.Lcd.printf("ERROR: %s (%d)", msg, code);
    
    if(M5.Speaker.isEnabled()) {
        M5.Speaker.tone(3000, 200);
        delay(200);
        M5.Speaker.tone(2000, 300);
    }
}

class AttackFilter {
private:
    std::map<String, int> counters;
    unsigned long lastReset = 0;

public:
    bool check(const String& type) {
        if(millis() - lastReset > 60000) {
            counters.clear();
            lastReset = millis();
        }
        return ++counters[type] <= 3;
    }
};
// Обработчик пакетов
AttackFilter filter; 

// 4. Объявим структуру заголовка управления (если не определена в esp_wifi_types.h)
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seq_ctrl;
    uint8_t payload[];
} wifi_pkt_mgmt_t;

// 5. Используем актуальные константы подтипов
#define WIFI_PKT_MGMT_BEACON     0x80
#define WIFI_PKT_MGMT_DEAUTH     0xC0
#define WIFI_PKT_MGMT_DISASSOC   0xA0

// 6. Исправленный обработчик пакетов
void sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    
    if(type != WIFI_PKT_MGMT) return;

    wifi_pkt_mgmt_t* mgmt = (wifi_pkt_mgmt_t*)pkt->payload;
    
    switch(pkt->payload[0]) { // Анализ первого байта payload
        case WIFI_PKT_MGMT_BEACON:
            beaconCounter++;
            break;
            
        case WIFI_PKT_MGMT_DEAUTH:
        case WIFI_PKT_MGMT_DISASSOC:
            if(filter.check("Deauth")) {
                deauthCounter++;
                logAttack("Deauth", mgmt->sa, mgmt->da);
            }
            break;
    }
}

void toggleDeauthDetection() {
    deauthEnabled = !deauthEnabled;
    preferences.putBool("deauth_en", deauthEnabled);
}

void toggleBeaconFloodDetection() {
    beaconFloodEnabled = !beaconFloodEnabled;
    preferences.putBool("beacon_en", beaconFloodEnabled);
}

void clearStats() {
    deauthCounter = 0;
    beaconCounter = 0;
    preferences.putUInt("attack_count", 0);
}

void connectToNetwork(const String& ssid, const String& pass) {
    WiFi.begin(ssid.c_str(), pass.c_str());

        // Устанавливаем флаги мониторинга
    targetSSID = ssid;
    //isMonitoring = false; // Будет установлено в true после успешного подключения
    
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(10, 10);
    M5.Lcd.printf("Connecting to:\n%s", ssid.c_str());
    
    int attempts = 0;
    while(WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        M5.Lcd.print(".");
        attempts++;
    }
    
    if(WiFi.status() == WL_CONNECTED) {
        // Сохраняем данные в память
        preferences.putString(ssid.c_str(), pass); // Сохраняем пароль
        M5.Lcd.printf("\nConnected!\nIP: %s", WiFi.localIP().toString().c_str());
    } else {
        M5.Lcd.print("\nConnection failed!");
        // Удаляем неверные данные
        preferences.remove("ssid");
        preferences.remove("pass");
    }
    delay(3000);
}

void setup() {
    M5.begin();
    M5.Imu.init();
    M5.Lcd.setRotation(1);
    M5.Lcd.fillScreen(TFT_BLACK);
    
    // Инициализация WiFi
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Загрузка сохраненных данных
    preferences.begin("monitor-config", true);
    String savedSSID = preferences.getString("ssid", "");
    String savedPass = preferences.getString("pass", "");
    targetSSID = preferences.getString("targetSSID", "");
    preferences.end();
    
    // Настройка WiFi драйвера
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    
    // Подключение к сохраненной сети
    if(savedSSID.length() > 0) {
        connectToNetwork(savedSSID, savedPass);
    }
    
    // Настройка параметров сканирования
    esp_wifi_set_promiscuous(false); // Отключаем promiscuous mode для обычного сканирования
    esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_54M);
  
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
//    esp_wifi_set_promiscuous_rx_cb(promiscuousPacketHandler);
    
    // Настройка фильтра только для управленияющих пакетов
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    
    // Если подключение не удалось, продолжаем как обычно
    if(WiFi.status() != WL_CONNECTED) {
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();
        
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);
        
        esp_err_t err = esp_wifi_set_promiscuous(true);
        if(err != ESP_OK) { /* обработка ошибки */ }
        err = esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_handler);
        if(err != ESP_OK) { /* обработка ошибки */ }
        
        esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

        M5.Lcd.setTextSize(1);
        M5.Lcd.setTextColor(WHITE);
    }
}


void loop() {
    M5.update();
    static bool inMenu = false;
    
    // Режим клавиатуры
    if(isKeyboardActive) {
        handleKeyboardInput();
        drawKeyboard();
        return;
    }

    // Обработка меню
    if(M5.BtnC.wasPressed()) {
        inMenu = !inMenu;
        refreshList = true;
    }

    if(!inMenu) {
        // Навигация по сетям (Кнопка A)
        if(M5.BtnA.wasPressed() && selectedIndex > 0) {
            selectedIndex--;
            refreshList = true;
        }
        
        // Обработка кнопки B
        if(M5.BtnB.wasPressed()) {
            // Проверка двойного нажатия
            if(millis() - lastPressTime < DOUBLE_PRESS_DELAY) {
                pressCount++;
                if(pressCount == 2) {
                    connectToSelectedNetwork(); // Двойное нажатие
                    pressCount = 0;
                }
            } else {
                pressCount = 1;
            }
            lastPressTime = millis();
            
            // Одиночное нажатие (только если не было двойного)
            if(pressCount == 1 && M5.BtnB.wasReleased()) {
                if(selectedIndex < apCount - 1) {
                    selectedIndex++;
                    refreshList = true;
                }
            }
        }

        // Автосканирование
        if(millis() - lastScan > SCAN_INTERVAL) {
            scanNetworks();
            lastScan = millis();
            refreshList = true;
        } 
        drawUI();
    } else {
        // Меню настроек
        if(M5.BtnA.wasPressed()) toggleDeauthDetection();
        if(M5.BtnB.wasPressed()) toggleBeaconFloodDetection();
        if(M5.BtnC.wasPressed()) clearStats();
    }
}

void scanNetworks() {
    WiFi.scanDelete(); // Очищаем предыдущие результаты
    int found = WiFi.scanNetworks(false, true, false, 300, 0);
    
    if(found == WIFI_SCAN_FAILED) {
        Serial.println("Scan failed!");
        return;
    }

    apCount = min(found, MAX_DISPLAY_APS);

    #if CONFIG_SPIRAM_SUPPORT
      aps.clear();
      aps.resize(apCount);
    #endif
    for(int i = 0; i < apCount; i++) {
        aps[i].ssid = WiFi.SSID(i).length() > 0 ? WiFi.SSID(i) : "<hidden>";
        aps[i].rssi = WiFi.RSSI(i);
        aps[i].channel = WiFi.channel(i);
        memcpy(aps[i].bssid, WiFi.BSSID(i), 6);
        aps[i].isEncrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
    }
    Serial.printf("Found %d networks\n", found);
    for(int i=0; i<apCount; i++) {
        Serial.printf("%d. %s (Ch:%d)\n", i+1, aps[i].ssid.c_str(), aps[i].channel);
    }
}

// Добавляем реализацию connectToSelectedNetwork()
void connectToSelectedNetwork() {
    if(apCount == 0 || selectedIndex < 0 || selectedIndex >= apCount) {
        M5.Lcd.print("No network selected!");
        delay(1000);
        return;
    }
    isKeyboardActive = true;
    passwordBuffer.reserve(MAX_PASSWORD_LEN); // Предварительное выделение памяти
    passwordBuffer = "";
    keyboardPos = 0;
    uppercase = false;


    // Проверяем сохраненный пароль
    String savedPass = preferences.getString(aps[selectedIndex].ssid.c_str(), "");
    
    if(savedPass.length() > 0) {
        // Подключаемся автоматически
        connectToNetwork(aps[selectedIndex].ssid, savedPass);
    } else {
        // Запрашиваем пароль
        isKeyboardActive = true;
        passwordBuffer = "";
        keyboardPos = 0;
        M5.Lcd.fillScreen(TFT_BLACK);
        drawKeyboard();
    }
}


void drawUI() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.printf("Networks (%d):\n", apCount);
    // Список сетей
    for(int i = 0; i < apCount; i++) {
        if(i == selectedIndex) {
            M5.Lcd.setTextColor(TFT_BLACK, TFT_GREEN);
            M5.Lcd.fillRect(0, 15 + i*25, M5.Lcd.width(), 20, TFT_GREEN);
        } else {
            M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        
        M5.Lcd.setCursor(5, 17 + i*25);
        M5.Lcd.printf("%02d. %-16s", i+1, aps[i].ssid.c_str());
        
        M5.Lcd.setCursor(5, 27 + i*25);
        M5.Lcd.printf("Ch:%2d RSSI:%3d", aps[i].channel, aps[i].rssi);
    }

    // Статусная строка
    M5.Lcd.setTextColor(TFT_GREEN, TFT_BLACK);
    M5.Lcd.setCursor(0, M5.Lcd.height() - 10);
    M5.Lcd.printf("Scan: %ds  %s", 
                (millis()-lastScan)/1000,
                inMenu ? "[MENU]" : "");


    // Статус атаки (без анимации)
    if(attackDetected) {
        M5.Lcd.setTextColor(TFT_RED, TFT_BLACK);
        M5.Lcd.setCursor(0, M5.Lcd.height() - 15);
        M5.Lcd.print("ATTACK DETECTED!");
    }

    // Статус последнего сканирования
    M5.Lcd.setTextColor(TFT_GREEN, TFT_BLACK);
    M5.Lcd.setCursor(0, M5.Lcd.height() - 25);
    M5.Lcd.printf("Last scan: %ds", (millis()-lastScan)/1000);
    refreshList = false;
}
//Функция отрисовки клавиатуры
void drawKeyboard() {
    M5.Lcd.fillScreen(BLACK);
    int currentSet = uppercase ? 1 : 0;
    currentSet = constrain(currentSet, 0, 2); // Ограничение выбора наборов
    
    // Заголовок с проверкой длины SSID
    String displaySSID = aps[selectedIndex].ssid;
    if(displaySSID.length() > 12) {
        displaySSID = displaySSID.substring(0, 9) + "...";
    }
    
    M5.Lcd.setTextColor(WHITE);
    M5.Lcd.setCursor(5, 2);
    M5.Lcd.printf("Network: %s", displaySSID.c_str());

    // Отображение пароля с маскировкой и обрезкой
    M5.Lcd.setCursor(5, 20);
    M5.Lcd.print("Password: ");
    if(passwordBuffer.length() > 15) {
        M5.Lcd.print("...");
        M5.Lcd.print(passwordBuffer.substring(passwordBuffer.length()-12));
    } else {
        M5.Lcd.print(passwordBuffer.c_str());
    }

    // Оптимизированная отрисовка клавиш
    const int keySpacing = 2;
    const int keyWidth = (M5.Lcd.width() - 10 - (KEY_COLS-1)*keySpacing) / KEY_COLS;
    const int keyHeight = 18;
    
    for(int row=0; row<KEY_ROWS; row++){
        for(int col=0; col<KEY_COLS; col++){
            int index = row*KEY_COLS + col;
            int x = 5 + col*(keyWidth + keySpacing);
            int y = 40 + row*(keyHeight + keySpacing);
            
            // Проверка выхода за пределы набора
            if(index >= strlen(charSets[currentSet])) break;

            // Рисуем рамку
            bool selected = (index == keyboardPos);
            M5.Lcd.fillRect(x, y, keyWidth, keyHeight, 
                          selected ? TFT_YELLOW : TFT_DARKGREY);
            
            // Центрируем символ
            char buf[2] = {charSets[currentSet][index], '\0'};
            M5.Lcd.setTextColor(selected ? TFT_BLACK : TFT_WHITE);
            M5.Lcd.setTextDatum(MC_DATUM);
            M5.Lcd.drawString(buf, x + keyWidth/2, y + keyHeight/2 - 2);
        }
    }
    for(int row=0; row<KEY_ROWS; row++){
        for(int col=0; col<KEY_COLS; col++){
        }
    }
    // Динамические подсказки
    M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Lcd.setTextDatum(BL_DATUM);
    M5.Lcd.drawString("A:Select B:Shift C:Back", 5, M5.Lcd.height()-5);
}

void handleKeyboardInput() {
    int currentSet = uppercase ? 1 : 0;
    currentSet = constrain(currentSet, 0, 2);
    int totalChars = strlen(charSets[currentSet]);
    
    // Обработка нажатий кнопок
    if(M5.BtnA.wasPressed()) {
        if(millis() - lastPressA < 300) pressCountA++;
        else pressCountA = 1;
        lastPressA = millis();
    }
    
    if(M5.BtnB.wasPressed()) {
        if(millis() - lastPressB < 300) pressCountB++;
        else pressCountB = 1;
        lastPressB = millis();
    }

    // Обработка кнопки B (горизонталь и раскладка)
    if(pressCountB > 0 && millis() - lastPressB >= 300) {
        if(pressCountB == 1) {
            // Однократное нажатие - движение по горизонтали
            int col = (keyboardPos % KEY_COLS + 1) % KEY_COLS;
            keyboardPos = (keyboardPos / KEY_COLS) * KEY_COLS + col;
        } else {
            // Двойное нажатие - смена раскладки
            uppercase = !uppercase;
            keyboardPos = 0;
        }
        pressCountB = 0;
    }

    // Обработка кнопки A: вертикаль, ввод и подтверждение
    if(pressCountA > 0 && millis() - lastPressA >= 300) {
        // Двойное нажатие - ввод символа
        if(pressCountA == 2) {
            if(passwordBuffer.length() < MAX_PASSWORD_LEN) {
                passwordBuffer += charSets[currentSet][keyboardPos];
            }
        }
        pressCountA = 0;
    }

    if(M5.BtnA.pressedFor(1500)) {  // Увеличенное время для избежания конфликтов
        if(passwordBuffer.length() >= 8) {
            connectToNetwork(aps[selectedIndex].ssid, passwordBuffer.c_str());
            isKeyboardActive = false;
            M5.Lcd.clear();
            refreshList = true;
        } else {
            M5.Lcd.setTextColor(TFT_RED, TFT_BLACK);
            M5.Lcd.println("Need 8+ characters!");
            delay(1000);
        }
    }

        // Обычное одиночное нажатие A (вертикальная навигация)
    else if(M5.BtnA.wasReleased() && !M5.BtnA.pressedFor(1500)) {
        int col = keyboardPos % KEY_COLS;
        int maxRow = (totalChars - 1 - col) / KEY_COLS;
        int newRow = (keyboardPos / KEY_COLS + 1) % (maxRow + 1);
        keyboardPos = newRow * KEY_COLS + col;
    }

    // Дополнительные проверки
    if(M5.BtnA.pressedFor(1000)) {
        if(passwordBuffer.length() >= 8) {
            connectToNetwork(aps[selectedIndex].ssid, passwordBuffer);
            isKeyboardActive = false;
            refreshList = true;
        }
    }
}
// Функция проверки поддельных AP
void checkRogueAPs() {
    for(int i = 0; i < apCount; i++) {
        if(aps[i].ssid.isEmpty()) continue; // Пропускаем скрытые сети
        
        for(int j = i+1; j < apCount; j++) {
            if(aps[j].ssid.isEmpty()) continue;
            
            // Сравниваем с учетом RSSI и канала
            if(aps[i].ssid == aps[j].ssid && 
               memcmp(aps[i].bssid, aps[j].bssid, 6) != 0 &&
               abs(aps[i].rssi - aps[j].rssi) < 10 && // Подозрительная схожесть силы сигнала
               aps[i].channel == aps[j].channel) {
                logAttack("Rogue AP", aps[j].bssid, aps[i].bssid);
                attackDetected = true;
            }
        }
    }
}

// Полная реализация logAttack
void logAttack(const char* type, const uint8_t* attacker = nullptr, const uint8_t* victim = nullptr) { 
    // Безопасное обновление счетчика атак
    unsigned int count = preferences.getUInt("attack_count", 0);
    if(count < UINT_MAX) {
      preferences.putUInt("attack_count", count + 1);
    }
    else if(attacker && victim) {
        // Логирование с MAC-адресами
    } else {
        // Логирование без MAC-адресов
        M5.Lcd.printf("ATTACK: %s", type);
    }

    // Форматированный вывод MAC-адресов
    char attackerMac[18];
    char victimMac[18];
    snprintf(attackerMac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        attacker[0], attacker[1], attacker[2], 
        attacker[3], attacker[4], attacker[5]); 

    snprintf(victimMac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        victim[0], victim[1], victim[2], 
        victim[3], victim[4], victim[5]);
    
    // Вывод на экран с защитой от переполнения
    M5.Lcd.setTextColor(TFT_RED, TFT_BLACK);
    M5.Lcd.fillRect(0, M5.Lcd.height()-40, M5.Lcd.width(), 20, TFT_BLACK);
    M5.Lcd.setCursor(2, M5.Lcd.height()-40);
    M5.Lcd.printf("%s\nAttacker: %s\nVictim: %s", type, "attacker_mac", "victim_mac");
}
//Детектор флуда запросов (Beacon Flood):
void mitigationActions(const String& attackType) {
    if (attackType == "Beacon Flood") {
        // Действия при обнаружении флуда Beacon:
        // 1. Смена канала
        const uint8_t safeChannels[] = {1, 6, 11};
        esp_wifi_set_channel(safeChannels[random(3)], WIFI_SECOND_CHAN_NONE);
        
        // 2. Логирование
        logAttack("Beacon flood mitigated");
        
        // 3. Дополнительные меры (опционально)
        // Например: блокировка подозрительных MAC-адресов
    }
}
void checkBeaconFlood() {
    static uint32_t lastBeaconCount = 0;
    if(millis() - lastBeaconCheck > 1000) {
        uint32_t currentRate = beaconCounter - lastBeaconCount;
        if(currentRate > BEACON_FLOOD_THRESHOLD) {
            logAttack("Beacon flood", nullptr, nullptr);
            mitigationActions("Beacon Flood");
            beaconCounter = 0;
        }
        lastBeaconCount = beaconCounter;
        lastBeaconCheck = millis();
    }
}
//Анализ подозрительной активности:

// Callback-функция для перехвата пакетов
void promiscuousPacketHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(type == WIFI_PKT_MGMT) { // Только управляющие пакеты
        wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
        switch(pkt->payload[0]) {
            case 0x80: rx_packets++; break; // Beacon
            case 0xC0: tx_packets++; break; // Deauth
            case 0xA0: tx_packets++; break; // Disassoc
        }
    }
}
void analyzeTrafficPatterns() {
    static uint32_t last_rx = 0;
    static uint32_t last_tx = 0;
    static unsigned long lastCheck = 0;
    
    if(millis() - lastCheck > 5000) {
        //uint32_t currentRx, currentTx;
        uint32_t current_rx = rx_packets;
        uint32_t current_tx = tx_packets;

        // Расчет дельты
        uint32_t rx_delta = current_rx - last_rx;
        uint32_t tx_delta = current_tx - last_tx;
            
            // Проверяем аномалии
            if((rx_delta > 5000 && tx_delta < 100) || 
               (tx_delta > 3000 && rx_delta < 50)) {
                logAttack("Traffic anomaly");
            }
            
            // Обновляем значения
            last_rx = current_rx;
            last_tx = current_tx;
            lastCheck = millis();
    }
}
//Система отображения статистики:
void drawStats() {
    // Использование двойной буферизации
    M5.Lcd.startWrite();
    
    // Область статистики
    M5.Lcd.setClipRect(0, 0, M5.Lcd.width(), 20);
    M5.Lcd.fillRect(0, 0, M5.Lcd.width(), 20, TFT_BLACK);
    M5.Lcd.setTextColor(TFT_GREEN, TFT_BLACK);
    M5.Lcd.drawString(
        "APs:" + String(apCount) + 
        "  Attacks:" + String(preferences.getUInt("attack_count", 0)), 
        2, 2);
    
    // Индикатор подключения
    bool connected = WiFi.status() == WL_CONNECTED;
    M5.Lcd.fillRoundRect(M5.Lcd.width()-18, 2, 16, 16, 3, 
                         connected ? TFT_GREEN : TFT_RED);
    
    M5.Lcd.endWrite();
}
//Меню управления мониторингом:
void drawMonitoringMenu() {
    M5.Lcd.fillScreen(TFT_BLACK);
    M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
    
    M5.Lcd.drawString("Monitoring Settings", 10, 10, 2);
    
    M5.Lcd.setCursor(20, 40);
    M5.Lcd.printf("[A] Deauth detect: %s", 
                 deauthEnabled ? "ENABLED" : "DISABLED");
    
    M5.Lcd.setCursor(20, 60);
    M5.Lcd.printf("[B] Beacon flood: %s", 
                 beaconFloodEnabled ? "ENABLED" : "DISABLED");
    
    M5.Lcd.setCursor(20, 80);
    M5.Lcd.print("[C] Reset all counters");
}
// Функция проверки: детектор Evil Twin
void detectEvilTwin() {
    if(WiFi.status() != WL_CONNECTED) return;

    String currentSSID = WiFi.SSID();
    uint8_t currentBSSID[6];
    memcpy(currentBSSID, WiFi.BSSID(), 6);
    
    for(int i = 0; i < apCount; i++) {
      if(aps[i].ssid == currentSSID && 
        memcmp(aps[i].bssid, WiFi.BSSID(), 6) != 0) {
          logAttack("Evil Twin detected");
        }
      }
  }

//Визуализация сетевой активности:
void drawSpectrumAnalyzer() {
    static uint8_t currentChannel = 1;
    static uint8_t spectrum[13] = {0};
    wifi_country_t country;
    
    // Сохраняем текущий канал
    esp_wifi_get_channel(&currentChannel, NULL);
    esp_wifi_get_country(&country);
    
    // Сбор данных
    for(int ch = country.schan; ch < country.schan + country.nchan; ch++) {
        if(ch > 13) break;
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(50);
        spectrum[ch-1] = (uint8_t)constrain(map(WiFi.RSSI(), -100, -50, 0, 100), 0, 100);
    }
    
    // Восстанавливаем канал
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    // Отрисовка
    M5.Lcd.fillRect(0, 20, M5.Lcd.width(), M5.Lcd.height()-40, TFT_BLACK);
    for(int i = 0; i < country.nchan; i++) {
        int ch = country.schan + i;
        int barHeight = map(spectrum[ch-1], 0, 100, 0, M5.Lcd.height()-60);
        int x = 10 + i*25;
        M5.Lcd.fillRect(x, M5.Lcd.height()-40-barHeight, 20, barHeight, TFT_GREEN);
        M5.Lcd.setTextColor(TFT_WHITE);
        M5.Lcd.drawNumber(ch, x+5, M5.Lcd.height()-30);
    }
}

//Расширенное меню безопасности:
void applySecurityPolicy() {
    esp_err_t err;
    switch(currentMode) {
        case BASIC:
            err = esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
            if(err != ESP_OK) logError("Power save", err);
            break;
            
        case ENHANCED: {
            wifi_promiscuous_filter_t filter = { .filter_mask = ENHANCED_FILTER_MASK };
            err = esp_wifi_set_promiscuous_filter(&filter);
            if(err != ESP_OK) logError("Promisc filter", err);
            break;
        }
            
        case PARANOID:
            err = esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_11M_L);
            if(err != ESP_OK) logError("TX rate", err);
            break;
    }
}
//Шифрование сохраненных данных:
void secureStore(const String& key, const String& value) {
    if(value.length() > 64) {
        logError("Value too long", value.length());
        return;
    }
    
    byte iv[12];
    byte tag[16];
    byte cipher[128] = {0};
    
    // Генерация случайного IV
    esp_fill_random(iv, sizeof(iv));
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    String masterKey = preferences.getString("masterKey", "");
    if(masterKey.length() != 32) {
        logError("Invalid master key", masterKey.length());
        return;
    }
    
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, 
                                (const byte*)masterKey.c_str(), 256);
    if(ret != 0) {
        logError("GCM init failed", ret);
        return;
    }
    
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                   value.length(), iv, sizeof(iv),
                                   NULL, 0, (const byte*)value.c_str(),
                                   cipher, sizeof(tag), tag);
                                   
    if(ret == 0) {
        preferences.putBytes((key + "_iv").c_str(), iv, sizeof(iv));
        preferences.putBytes((key + "_tag").c_str(), tag, sizeof(tag));
        preferences.putBytes(key.c_str(), cipher, value.length());
    }
    mbedtls_gcm_free(&gcm);
}
//Система проверки целостности:

//Расширенный интерфейс пользователя:
void drawDashboard() {
    static unsigned long lastRedraw = 0;
    if(millis() - lastRedraw < 500) return;
    
    M5.Lcd.fillScreen(TFT_BLACK);
    M5.Lcd.setTextColor(TFT_WHITE);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.printf("Threat Level: %d/10", calculateThreatLevel());

    // Секция статуса
    M5.Lcd.setTextColor(TFT_WHITE);
    M5.Lcd.drawString("Security Monitor", 5, 5);
    
    // Уровень угрозы
    int threat = calculateThreatLevel();
    M5.Lcd.setTextColor(threat > 5 ? TFT_RED : TFT_YELLOW);
    M5.Lcd.drawString("Threat: " + String(threat) + "/10", 5, 25);
    
    M5.Lcd.endWrite();
    lastRedraw = millis();
}

// Вспомогательные функции
uint16_t threatColor() {
    int level = calculateThreatLevel();
    return M5.Lcd.color565(
        constrain(level * 25, 0, 255),
        constrain(255 - level * 25, 0, 255),
        0
    );
}
// Реализация drawNetworkList
void drawNetworkList() {
    M5.Lcd.fillScreen(TFT_BLACK);
    M5.Lcd.setTextColor(TFT_YELLOW);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.printf("Available Networks [%d]:", apCount);

    for(int i = 0; i < apCount; i++) {
        if(i == selectedIndex) {
            M5.Lcd.setTextColor(TFT_BLACK, TFT_GREEN);
        } else {
            M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        
        M5.Lcd.setCursor(0, 20 + i*20);
        M5.Lcd.printf("%02d. %-16s Ch:%2d", 
                     i+1, 
                     aps[i].ssid.c_str(), 
                     aps[i].channel);
    }
}

// Функция для запуска мониторинга
void startNetworkMonitoring() {
    // Сохраняем параметры сети
    targetSSID = WiFi.SSID();
    memcpy(targetBSSID, WiFi.BSSID(), 6);

    if(WiFi.status() == WL_CONNECTED) {
        memcpy(targetBSSID, WiFi.BSSID(), 6); // Используем правильную переменную
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(WiFi.channel(), WIFI_SECOND_CHAN_NONE);
    }
    
    // Настраиваем сниффер
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(WiFi.channel(), WIFI_SECOND_CHAN_NONE);
    logAttack("Monitoring started", targetBSSID, nullptr);
}
// Функция отрисовки экрана мониторинга
void drawMonitoringScreen() {
    M5.Lcd.fillScreen(TFT_BLACK);
    
    // Заголовок
    M5.Lcd.setTextColor(TFT_GREEN);
    M5.Lcd.drawString("Monitoring:", 5, 5);
    M5.Lcd.drawString(targetSSID, 5, 25);

    // Статистика
    M5.Lcd.drawString("Threats detected:", 5, 60);
    M5.Lcd.drawNumber(deauthCounter, 120, 60);
    
    // Индикатор подключения
//    drawConnectionStatus();
}
void drawConnectionStatus() {
    int x = M5.Lcd.width() - 25;
    int y = 5;
    M5.Lcd.fillCircle(x, y, 10, WiFi.status() == WL_CONNECTED ? TFT_GREEN : TFT_RED);
}
void handleMonitoringInput() {
    if(M5.BtnA.wasPressed()) {
        // Кнопка A - пауза мониторинга
        isMonitoring = false;
    }
    if(M5.BtnB.wasPressed()) {
        // Кнопка B - детальная статистика
        showDetailedStats();
    }
}
void drawActivityGraph() {
    static int graphData[10] = {0};
    static int index = 0;
    
    graphData[index] = deauthCounter;
    index = (index + 1) % 10;
    
    for(int i=0; i<10; i++) {
        int height = map(graphData[i], 0, 50, 0, 50);
        M5.Lcd.fillRect(i*12, 100-height, 10, height, TFT_RED);
    }
}
// Остановка мониторинга сети
void stopNetworkMonitoring() {
    esp_wifi_set_promiscuous(false);
    attackDetected = false;
    deauthCounter = 0;
    beaconCounter = 0;
    logAttack("Monitoring stopped");
}

// Обработка в режиме мониторинга
void handleMonitoringMode() {
    checkBeaconFlood();
    detectEvilTwin();
    analyzeTrafficPatterns();
    drawMonitoringScreen();
}

// Обработка в обычном режиме
void handleNormalMode() {
    if(M5.BtnA.wasPressed() && selectedIndex > 0) selectedIndex--;
    if(M5.BtnB.wasPressed() && selectedIndex < apCount-1) selectedIndex++;
    if(millis() - lastScan > SCAN_INTERVAL) scanNetworks();
}

// Детальная статистика
void showDetailedStats() {
    M5.Lcd.fillScreen(TFT_BLACK);
    M5.Lcd.setTextColor(TFT_WHITE);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.printf("Deauth attacks: %d\n", deauthCounter);
    M5.Lcd.printf("Beacon floods: %d\n", beaconCounter);
    M5.Lcd.printf("Last attack: %ds\n", (millis()-lastDeauthReset)/1000);
}
