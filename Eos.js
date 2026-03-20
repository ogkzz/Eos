/**
 * PROJECT SPECIFICATION — r eOS Scanner (iOS / Scriptable)
 * Versão: 2.0 (Enterprise Extended)
 * Plataforma: Scriptable
 * Aplicação alvo: Free Fire
 * Formato de entrega: Código único completo (Eos.js)
 */

// ==========================================
// 1. CONFIGURAÇÕES E CONSTANTES
// ==========================================
const CONFIG = {
  VERSION: "2.0 (Enterprise Extended)",
  TARGET_APP: "Free Fire",
  THRESHOLDS: {
    TIME_DIFF_MAX: 60, // Segundos de diferença máxima para OK
    OLD_FILE_MIN: 15,  // Minutos para considerar arquivo antigo
    SHORT_UPTIME_MIN: 20 // Minutos para considerar uptime curto
  },
  APIS: {
    TIME: [
      "https://worldtimeapi.org/api/timezone/Etc/UTC",
      "https://timeapi.io/api/Time/current/zone?timeZone=UTC"
    ],
    IP_INFO: "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
  },
  SUSPECT_LISTS: {
    ASNS: ["AS47583", "AS35916", "AS14061", "AS16509", "AS15169"], 
    TLDS: [".site", ".store", ".xyz", ".online", ".tech"],
    KEYWORDS: ["proxy", "cheat", "mitm", "tunnel", "vpn", "potatso", "shadowsocks", "wireguard"],
    BANNERS: ["nginx", "apache", "ubuntu", "debian", "centos"]
  }
};

// ==========================================
// 2. UTILITÁRIOS E HELPERS
// ==========================================
class Utils {
  static async fetchJSON(url) {
    try {
      let req = new Request(url);
      req.timeoutInterval = 10;
      return await req.loadJSON();
    } catch (e) {
      return null;
    }
  }

  static formatTimestamp(epoch) {
    return new Date(epoch).toLocaleString('pt-BR');
  }

  static getDiffMinutes(t1, t2) {
    return Math.abs(t1 - t2) / (1000 * 60);
  }

  static getDiffSeconds(t1, t2) {
    return Math.abs(t1 - t2) / 1000;
  }
}

// ==========================================
// 3. MÓDULO PRINCIPAL
// ==========================================
class EosScanner {
  constructor() {
    this.data = {
      local: {
        timestamp: Date.now(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        device: Device.model(),
        system: Device.systemName() + " " + Device.systemVersion()
      },
      external: {},
      detections: [],
      score: 0,
      logs: []
    };
  }

  log(msg) {
    const entry = `[${new Date().toISOString()}] ${msg}`;
    this.data.logs.push(entry);
    console.log(entry);
  }

  addDetection(id, desc, points) {
    this.data.detections.push({ id, desc, points });
    this.data.score += points;
    this.log(`DETECÇÃO: ${id} (+${points} pts) - ${desc}`);
  }

  async collectData() {
    this.log("Iniciando coleta de dados...");
    
    let timeData = null;
    for (let url of CONFIG.APIS.TIME) {
      this.log(`Consultando API de tempo: ${url}`);
      timeData = await Utils.fetchJSON(url);
      if (timeData) break;
    }
    
    if (timeData) {
      const extTimestamp = timeData.unixtime ? timeData.unixtime * 1000 : new Date(timeData.dateTime + (timeData.dateTime.endsWith("Z") ? "" : "Z")).getTime();
      this.data.external.timestamp = extTimestamp;
    }

    this.log("Consultando informações de rede...");
    const ipInfo = await Utils.fetchJSON(CONFIG.APIS.IP_INFO);
    if (ipInfo && ipInfo.status === "success") {
      this.data.external.network = ipInfo;
    }
  }

  analyzeTime() {
    if (!this.data.external.timestamp) return;
    const diff = Utils.getDiffSeconds(this.data.local.timestamp, this.data.external.timestamp);
    this.log(`Diferença de tempo: ${diff.toFixed(2)}s`);
    if (diff > CONFIG.THRESHOLDS.TIME_DIFF_MAX) {
      this.addDetection("TIME_DRIFT", `Diferença de horário elevada (${diff.toFixed(0)}s)`, 2);
    }
  }

  async analyzeNetwork() {
    const net = this.data.external.network;
    if (!net) return;

    const isHosting = /hosting|vps|datacenter|cloud/i.test(net.isp) || /hosting|vps|datacenter|cloud/i.test(net.org);
    if (isHosting) {
      this.addDetection("VPS_HOSTING", `IP identificado como infraestrutura de Datacenter/VPS (${net.isp})`, 4);
    }

    const currentASN = net.as ? net.as.split(" ")[0] : "";
    if (CONFIG.SUSPECT_LISTS.ASNS.includes(currentASN)) {
      this.addDetection("SUSPECT_ASN", `ASN suspeito detectado: ${currentASN}`, 3);
    }

    if (net.reverse) {
      const hasSuspectKeyword = CONFIG.SUSPECT_LISTS.KEYWORDS.some(kw => net.reverse.toLowerCase().includes(kw));
      if (hasSuspectKeyword) {
        this.addDetection("SUSPECT_RDNS", `rDNS contém palavras-chave suspeitas: ${net.reverse}`, 2);
      }
    }

    await this.probeNetwork(net.query);
  }

  async probeNetwork(ip) {
    try {
      let req = new Request(`http://${ip}`);
      req.timeoutInterval = 5;
      await req.load();
      let serverHeader = req.response.headers["Server"] || "";
      if (CONFIG.SUSPECT_LISTS.BANNERS.some(b => serverHeader.toLowerCase().includes(b))) {
        this.addDetection("HTTP_PROBE", `Banner de servidor suspeito detectado: ${serverHeader}`, 3);
      }
    } catch (e) {}
  }

  async analyzePrivacyReport() {
    this.log("Analisando App Privacy Report...");
    let reportData = null;
    try {
      if (args.fileURLs && args.fileURLs.length > 0) {
        const path = args.fileURLs[0];
        const content = FileManager.local().readString(path);
        reportData = JSON.parse(content);
      }
    } catch (e) {
      this.log("Nenhum App Privacy Report válido encontrado.");
    }

    if (!reportData) return;

    if (!reportData.exportTimestamp || !reportData.networkDetails) {
      this.addDetection("INVALID_REPORT", "Estrutura do App Privacy Report inválida ou adulterada", 3);
    }

    const reportTime = new Date(reportData.exportTimestamp).getTime();
    const ageMinutes = Utils.getDiffMinutes(this.data.local.timestamp, reportTime);
    if (ageMinutes > CONFIG.THRESHOLDS.OLD_FILE_MIN) {
      this.addDetection("OLD_FILE", `Relatório com mais de ${CONFIG.THRESHOLDS.OLD_FILE_MIN} minutos (${ageMinutes.toFixed(0)} min)`, 1);
    }

    if (reportData.networkDetails && reportData.networkDetails.length > 0) {
      const firstEvent = new Date(reportData.networkDetails[0].timeStamp).getTime();
      const uptime = Utils.getDiffMinutes(this.data.local.timestamp, firstEvent);
      if (uptime < CONFIG.THRESHOLDS.SHORT_UPTIME_MIN) {
        this.addDetection("SHORT_UPTIME", `Período de atividade analisado insuficiente (${uptime.toFixed(0)} min)`, 2);
      }

      let hasFF = false;
      let appStoreAfterFF = false;
      let ffTimestamp = 0;

      for (let entry of reportData.networkDetails) {
        const domain = entry.domain.toLowerCase();
        const timestamp = new Date(entry.timeStamp).getTime();

        if (domain.includes("app-measurement.com") || domain.includes("freefire")) {
          hasFF = true;
          ffTimestamp = timestamp;
        }

        if (CONFIG.SUSPECT_LISTS.KEYWORDS.some(kw => domain.includes(kw))) {
          this.addDetection("SUSPECT_DOMAIN", `Domínio suspeito encontrado: ${domain}`, 2);
        }

        if (CONFIG.SUSPECT_LISTS.TLDS.some(tld => domain.endsWith(tld))) {
          this.addDetection("SUSPECT_TLD", `TLD suspeito detectado: ${domain}`, 1);
        }

        if (domain.includes("itunes.apple.com") || domain.includes("apple-dns.net")) {
          if (hasFF && timestamp > ffTimestamp) {
            appStoreAfterFF = true;
          }
        }
      }

      if (appStoreAfterFF) {
        this.addDetection("APPSTORE_AFTER_FF", "Abertura da App Store detectada após atividade no jogo", 2);
      }
    }
  }

  getClassification() {
    const score = this.data.score;
    if (score >= 8) return "CRÍTICO";
    if (score >= 4) return "SUSPEITO";
    return "OK";
  }

  async generateOutput() {
    const status = this.getClassification();
    const result = {
      status: status,
      score: this.data.score,
      detections: this.data.detections,
      timestamp: Utils.formatTimestamp(this.data.local.timestamp),
      network: this.data.external.network ? {
        ip: this.data.external.network.query,
        isp: this.data.external.network.isp,
        as: this.data.external.network.as
      } : { ip: "Indisponível", isp: "Indisponível", as: "Indisponível" }
    };

    console.log("==========================================");
    console.log(`   r eOS Scanner - ${CONFIG.VERSION}`);
    console.log("==========================================");
    console.log(`STATUS: ${result.status}`);
    console.log(`SCORE:  ${result.score}`);
    console.log(`HORA:   ${result.timestamp}`);
    console.log("------------------------------------------");
    
    if (result.detections.length > 0) {
      console.log("DETECÇÕES:");
      result.detections.forEach(d => console.log(`- [${d.id}] ${d.desc}`));
    } else {
      console.log("Nenhuma irregularidade detectada.");
    }
    
    console.log("------------------------------------------");
    console.log("DADOS TÉCNICOS:");
    console.log(`IP:  ${result.network.ip}`);
    console.log(`ISP: ${result.network.isp}`);
    console.log(`ASN: ${result.network.as}`);
    console.log("==========================================");

    if (config.runsInApp) {
      let alert = new Alert();
      alert.title = `Resultado: ${result.status}`;
      alert.message = `Score: ${result.score}\n\n` + 
                      (result.detections.length > 0 
                        ? "Motivos:\n" + result.detections.map(d => `• ${d.desc}`).join("\n")
                        : "Ambiente limpo.");
      alert.addAction("Fechar");
      await alert.presentAlert();
    }
    return result;
  }

  async run() {
    try {
      await this.collectData();
      this.analyzeTime();
      await this.analyzeNetwork();
      await this.analyzePrivacyReport();
      return await this.generateOutput();
    } catch (e) {
      this.log(`ERRO CRÍTICO: ${e.message}`);
    }
  }
}

const scanner = new EosScanner();
await scanner.run();
