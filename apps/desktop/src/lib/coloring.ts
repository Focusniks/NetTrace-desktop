// Packet coloring rules. Colors are low-saturation tints that stay readable
// on the dark theme; red/orange tints are reserved for problems.

export interface ColorRule {
  name: string;
  filter: string;
  bg: string;
  fg: string;
  enabled: boolean;
}

export const DEFAULT_RULES: ColorRule[] = [
  { name: "Повреждённые пакеты", filter: "_ws.malformed", bg: "#4a1f22", fg: "#ffb4b4", enabled: true },
  { name: "Проблемы TCP", filter: "tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive", bg: "#3d2318", fg: "#ffc59e", enabled: true },
  { name: "TCP RST", filter: "tcp.flags.reset == 1", bg: "#3a1e26", fg: "#f4a6b8", enabled: true },
  { name: "TCP SYN/FIN", filter: "tcp.flags.syn == 1 || tcp.flags.fin == 1", bg: "#252b33", fg: "#c8d0db", enabled: true },
  { name: "ICMP: ошибки", filter: "icmp.type == 3 || icmp.type == 11 || icmpv6.type < 128", bg: "#33281a", fg: "#e8c48c", enabled: true },
  { name: "ARP", filter: "arp", bg: "#2c2a1c", fg: "#e2d9a6", enabled: true },
  { name: "ICMP", filter: "icmp || icmpv6", bg: "#2d2433", fg: "#d9c2e8", enabled: true },
  { name: "DNS", filter: "dns", bg: "#1b2a3a", fg: "#a8cdf2", enabled: true },
  { name: "HTTP", filter: "http", bg: "#1d3024", fg: "#acdcb8", enabled: true },
  { name: "TLS", filter: "tls", bg: "#262338", fg: "#c4bdf0", enabled: true },
  { name: "DHCP / NTP", filter: "dhcp || ntp", bg: "#1d2f30", fg: "#a6dcd8", enabled: true },
  { name: "UDP", filter: "udp", bg: "#1a2629", fg: "#b9cdd1", enabled: true },
  { name: "TCP", filter: "tcp", bg: "#1d2129", fg: "#c3cad6", enabled: true },
];
