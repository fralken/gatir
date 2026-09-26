// Evaluates a PAC file in V8 (Node), as an independent reference for
// tests/pac_file.rs.
//
//   node pac-oracle.js proxy.pac cases.tsv > expected.tsv
//
// cases.tsv has one `url<TAB>host` per line; the output has
// `url<TAB>host<TAB>result` (or `ERR message`). The helpers are written here
// again, on purpose, and the name lookups are the same fake ones as in the test:
// a name has an address made from a hash of it, and this machine is 10.10.10.10.

const fs = require("fs");
const vm = require("vm");

const fnv32 = (text) => {
  let hash = 2166136261;
  for (const byte of Buffer.from(text.toLowerCase())) {
    hash ^= byte;
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0;
};
const isIpv4 = (text) => /^\d+\.\d+\.\d+\.\d+$/.test(text);
const toNumber = (address) => address.split(".").reduce((all, octet) => ((all << 8) | +octet) >>> 0, 0);

const helpers = {
  dnsDomainIs: (host, domain) => host.toLowerCase().endsWith(domain.toLowerCase()),
  localHostOrDomainIs: (host, hostdom) =>
    host.toLowerCase() === hostdom.toLowerCase() ||
    (!host.includes(".") && hostdom.toLowerCase().startsWith(host.toLowerCase() + ".")),
  isPlainHostName: (host) => !host.includes("."),
  dnsDomainLevels: (host) => (host.match(/\./g) || []).length,
  shExpMatch: (text, glob) =>
    new RegExp("^" + glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "s").test(text),
  dnsResolve: (host) => {
    if (isIpv4(host)) return host;
    const h = fnv32(host);
    return `10.${(h >> 8) & 255}.${(h >> 16) & 255}.${1 + (h % 250)}`;
  },
  myIpAddress: () => "10.10.10.10",
};
helpers.isInNet = (host, pattern, mask) => {
  const address = helpers.dnsResolve(host);
  return ((toNumber(address) & toNumber(mask)) >>> 0) === ((toNumber(pattern) & toNumber(mask)) >>> 0);
};

const [pacPath, casesPath] = process.argv.slice(2);
const context = vm.createContext({ ...helpers });
vm.runInContext(fs.readFileSync(pacPath, "utf8"), context);

const lines = fs.readFileSync(casesPath, "utf8").split("\n").filter(Boolean);
for (const line of lines) {
  const [url, host] = line.split("\t");
  let result;
  try {
    result = context.FindProxyForURL(url, host);
  } catch (error) {
    result = `ERR ${error.message}`;
  }
  console.log(`${url}\t${host}\t${result}`);
}
