import axios from 'axios';
import { ScanConfig, ScanResult, ScanProgress } from '../types';

const API_BASE_URL = 'http://localhost:3001/api';

export const startScan = async (config: ScanConfig): Promise<string> => {
  const response = await axios.post(`${API_BASE_URL}/scan`, config);
  return response.data.scanId;
};

export const getScanProgress = async (scanId: string): Promise<ScanProgress> => {
  const response = await axios.get(`${API_BASE_URL}/scan/${scanId}/progress`);
  return response.data;
};

export const getScanResults = async (scanId: string): Promise<ScanResult[]> => {
  const response = await axios.get(`${API_BASE_URL}/scan/${scanId}/results`);
  return response.data;
};

export const cancelScan = async (scanId: string): Promise<void> => {
  await axios.post(`${API_BASE_URL}/scan/${scanId}/cancel`);
};

export const getRules = async (): Promise<any[]> => {
  const response = await axios.get(`${API_BASE_URL}/rules`);
  return response.data;
};

export const addRule = async (rule: any): Promise<void> => {
  await axios.post(`${API_BASE_URL}/rules`, rule);
};

export const updateRule = async (ruleId: string, rule: any): Promise<void> => {
  await axios.put(`${API_BASE_URL}/rules/${ruleId}`, rule);
};

export const deleteRule = async (ruleId: string): Promise<void> => {
  await axios.delete(`${API_BASE_URL}/rules/${ruleId}`);
};
