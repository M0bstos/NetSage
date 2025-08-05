/**
 * ServiceMappings
 * 
 * Provides mappings between services and their standard ports
 */

/**
 * Standard service to port mappings
 * Each entry contains:
 * - ports: Array of common ports for the service
 * - protocol: Default protocol (tcp/udp)
 * - description: Brief description of the service
 */
const SERVICE_PORT_MAPPINGS = {
  // Web Services
  'http': {
    ports: [80, 8080, 8000, 8008, 8081, 8888],
    protocol: 'tcp',
    description: 'HTTP web server'
  },
  'https': {
    ports: [443, 8443, 4443, 9443],
    protocol: 'tcp',
    description: 'HTTPS web server (HTTP over TLS/SSL)'
  },
  'http-alt': {
    ports: [8080, 8000, 8008, 8088, 8081, 8090],
    protocol: 'tcp',
    description: 'HTTP on alternative ports'
  },
  
  // Mail Services
  'smtp': {
    ports: [25, 465, 587, 2525],
    protocol: 'tcp',
    description: 'Simple Mail Transfer Protocol'
  },
  'pop3': {
    ports: [110, 995],
    protocol: 'tcp',
    description: 'Post Office Protocol v3'
  },
  'imap': {
    ports: [143, 993],
    protocol: 'tcp',
    description: 'Internet Message Access Protocol'
  },
  
  // File Transfer
  'ftp': {
    ports: [21],
    protocol: 'tcp',
    description: 'File Transfer Protocol'
  },
  'ftps': {
    ports: [990],
    protocol: 'tcp',
    description: 'FTP over SSL/TLS'
  },
  'sftp': {
    ports: [22],
    protocol: 'tcp',
    description: 'SSH File Transfer Protocol'
  },
  
  // Remote Access
  'ssh': {
    ports: [22],
    protocol: 'tcp',
    description: 'Secure Shell'
  },
  'telnet': {
    ports: [23],
    protocol: 'tcp',
    description: 'Telnet protocol'
  },
  'rdp': {
    ports: [3389],
    protocol: 'tcp',
    description: 'Remote Desktop Protocol'
  },
  'vnc': {
    ports: [5900, 5901, 5902, 5903, 5800],
    protocol: 'tcp',
    description: 'Virtual Network Computing'
  },
  
  // Database Services
  'mysql': {
    ports: [3306],
    protocol: 'tcp',
    description: 'MySQL Database'
  },
  'mariadb': {
    ports: [3306],
    protocol: 'tcp',
    description: 'MariaDB Database'
  },
  'postgresql': {
    ports: [5432],
    protocol: 'tcp',
    description: 'PostgreSQL Database'
  },
  'mongodb': {
    ports: [27017, 27018, 27019],
    protocol: 'tcp',
    description: 'MongoDB Database'
  },
  'redis': {
    ports: [6379],
    protocol: 'tcp',
    description: 'Redis Database'
  },
  'mssql': {
    ports: [1433],
    protocol: 'tcp',
    description: 'Microsoft SQL Server'
  },
  'oracle': {
    ports: [1521, 1630],
    protocol: 'tcp',
    description: 'Oracle Database'
  },
  
  // DNS and Network Services
  'dns': {
    ports: [53],
    protocol: 'udp',
    description: 'Domain Name Service'
  },
  'dhcp': {
    ports: [67, 68],
    protocol: 'udp',
    description: 'Dynamic Host Configuration Protocol'
  },
  'ntp': {
    ports: [123],
    protocol: 'udp',
    description: 'Network Time Protocol'
  },
  'snmp': {
    ports: [161, 162],
    protocol: 'udp',
    description: 'Simple Network Management Protocol'
  },
  'ldap': {
    ports: [389, 636],
    protocol: 'tcp',
    description: 'Lightweight Directory Access Protocol'
  },
  
  // Communication Services
  'irc': {
    ports: [6667, 6697],
    protocol: 'tcp',
    description: 'Internet Relay Chat'
  },
  'xmpp': {
    ports: [5222, 5223],
    protocol: 'tcp',
    description: 'Extensible Messaging and Presence Protocol'
  },
  'sip': {
    ports: [5060, 5061],
    protocol: 'udp',
    description: 'Session Initiation Protocol'
  },
  
  // Other Common Services
  'nfs': {
    ports: [2049],
    protocol: 'tcp',
    description: 'Network File System'
  },
  'smb': {
    ports: [445],
    protocol: 'tcp',
    description: 'Server Message Block'
  },
  'netbios': {
    ports: [137, 138, 139],
    protocol: 'tcp',
    description: 'NetBIOS'
  },
  'kerberos': {
    ports: [88],
    protocol: 'tcp',
    description: 'Kerberos authentication'
  },
  'elasticsearch': {
    ports: [9200, 9300],
    protocol: 'tcp',
    description: 'Elasticsearch'
  },
  'docker': {
    ports: [2375, 2376],
    protocol: 'tcp',
    description: 'Docker API'
  },
  'kubernetes': {
    ports: [6443],
    protocol: 'tcp',
    description: 'Kubernetes API server'
  }
};

/**
 * Protocol to default port mappings
 * Used when URL includes protocol but no explicit port
 */
const PROTOCOL_PORT_MAPPINGS = {
  'http': 80,
  'https': 443,
  'ftp': 21,
  'ftps': 990,
  'ssh': 22,
  'telnet': 23,
  'smtp': 25,
  'smtps': 465,
  'pop3': 110,
  'pop3s': 995,
  'imap': 143,
  'imaps': 993,
  'ldap': 389,
  'ldaps': 636,
  'mqtt': 1883,
  'mqtts': 8883,
  'redis': 6379,
  'mongodb': 27017,
  'mysql': 3306,
  'postgresql': 5432,
  'rdp': 3389,
  'vnc': 5900
};

class ServiceMappings {
  /**
   * Get ports commonly used by a service
   * @param {string} serviceName - Name of the service
   * @returns {Array} - Array of common ports for the service
   */
  getPortsForService(serviceName) {
    if (!serviceName) return [];
    
    // Normalize service name to lowercase and remove whitespace
    const normalizedName = serviceName.toLowerCase().trim();
    
    // Check for exact match
    if (SERVICE_PORT_MAPPINGS[normalizedName]) {
      return SERVICE_PORT_MAPPINGS[normalizedName].ports;
    }
    
    // Check for partial matches
    for (const service in SERVICE_PORT_MAPPINGS) {
      if (normalizedName.includes(service) || service.includes(normalizedName)) {
        return SERVICE_PORT_MAPPINGS[service].ports;
      }
    }
    
    // No match found
    return [];
  }
  
  /**
   * Get the default port for a protocol
   * @param {string} protocol - Protocol name (e.g., http, https)
   * @returns {number|null} - Default port or null if not found
   */
  getDefaultPortForProtocol(protocol) {
    if (!protocol) return null;
    
    const normalizedProtocol = protocol.toLowerCase().trim();
    return PROTOCOL_PORT_MAPPINGS[normalizedProtocol] || null;
  }
  
  /**
   * Get full service information for a service name
   * @param {string} serviceName - Name of the service
   * @returns {Object|null} - Service information or null if not found
   */
  getServiceInfo(serviceName) {
    if (!serviceName) return null;
    
    const normalizedName = serviceName.toLowerCase().trim();
    
    // Check for exact match
    if (SERVICE_PORT_MAPPINGS[normalizedName]) {
      return {
        service: normalizedName,
        ...SERVICE_PORT_MAPPINGS[normalizedName]
      };
    }
    
    // Check for partial matches
    for (const service in SERVICE_PORT_MAPPINGS) {
      if (normalizedName.includes(service) || service.includes(normalizedName)) {
        return {
          service: service,
          ...SERVICE_PORT_MAPPINGS[service]
        };
      }
    }
    
    // No match found
    return null;
  }
  
  /**
   * Get all known services that might run on a specific port
   * @param {number} port - Port number
   * @param {string} protocol - Protocol (tcp/udp), defaults to tcp
   * @returns {Array} - Array of service names that might use this port
   */
  getServicesForPort(port, protocol = 'tcp') {
    if (!port) return [];
    
    const normalizedProtocol = protocol.toLowerCase().trim();
    const results = [];
    
    for (const service in SERVICE_PORT_MAPPINGS) {
      const mapping = SERVICE_PORT_MAPPINGS[service];
      if (mapping.protocol === normalizedProtocol && mapping.ports.includes(port)) {
        results.push(service);
      }
    }
    
    return results;
  }
  
  /**
   * Get all known service mappings
   * @returns {Object} - All service mappings
   */
  getAllServiceMappings() {
    return SERVICE_PORT_MAPPINGS;
  }
  
  /**
   * Get all known protocol mappings
   * @returns {Object} - All protocol mappings
   */
  getAllProtocolMappings() {
    return PROTOCOL_PORT_MAPPINGS;
  }
}

module.exports = ServiceMappings;
