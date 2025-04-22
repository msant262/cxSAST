import { Rule } from '../types';

export const defaultRules: Rule[] = [
  {
    id: 'buffer-overflow',
    name: 'Buffer Overflow',
    description: 'Detects potential buffer overflow vulnerabilities',
    pattern: 'strcpy|strcat|sprintf|gets',
    severity: 'HIGH',
    category: 'A01:2021-Broken Access Control',
    enabled: true
  },
  {
    id: 'sql-injection',
    name: 'SQL Injection',
    description: 'Detects potential SQL injection vulnerabilities',
    pattern: 'sqlite3_exec|mysql_query|pg_exec',
    severity: 'CRITICAL',
    category: 'A03:2021-Injection',
    enabled: true
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    description: 'Detects potential XSS vulnerabilities in web applications',
    pattern: 'printf|sprintf|fprintf.*%s',
    severity: 'HIGH',
    category: 'A03:2021-Injection',
    enabled: true
  },
  {
    id: 'memory-leak',
    name: 'Memory Leak',
    description: 'Detects potential memory leaks',
    pattern: 'malloc|calloc|realloc.*[^free]',
    severity: 'MEDIUM',
    category: 'A04:2021-Insecure Design',
    enabled: true
  },
  {
    id: 'hardcoded-credentials',
    name: 'Hardcoded Credentials',
    description: 'Detects hardcoded passwords and credentials',
    pattern: 'password|passwd|secret|key|token',
    severity: 'CRITICAL',
    category: 'A07:2021-Identification and Authentication Failures',
    enabled: true
  },
  {
    id: 'insecure-crypto',
    name: 'Insecure Cryptography',
    description: 'Detects use of insecure cryptographic functions',
    pattern: 'MD5|SHA1|DES|RC4',
    severity: 'HIGH',
    category: 'A02:2021-Cryptographic Failures',
    enabled: true
  }
];
