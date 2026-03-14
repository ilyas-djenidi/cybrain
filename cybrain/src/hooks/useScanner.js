import { useState } from 'react';
import axios from 'axios';
import {
    API_ENDPOINTS,
    sortBySeverity,
    formatFinding
} from '../utils/logicProtection';

// Derive base backend URL from existing endpoints
const BACKEND = API_ENDPOINTS.SCAN_URL?.replace('/scan_url', '') || 'http://127.0.0.1:5000';


export const useScanner = () => {
    const [findings, setFindings]   = useState([]);
    const [loading,  setLoading]    = useState(false);
    const [error,    setError]      = useState(null);
    const [total,    setTotal]      = useState(0);

    const handleResults = (data) => {
        const raw     = data.results || data.findings || [];
        const sorted  = sortBySeverity(raw);
        setFindings(sorted);
        setTotal(sorted.length);
    };

    const analyzeConfig = async (configText) => {
        if (!configText?.trim()) return;
        setLoading(true);
        setError(null);
        try {
            const { data } = await axios.post(
                API_ENDPOINTS.ANALYZE,
                { config: configText },
                { headers: { 'Content-Type': 'application/json' } }
            );
            handleResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    const analyzeFile = async (file) => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const form = new FormData();
            form.append('file', file);
            const { data } = await axios.post(
                API_ENDPOINTS.ANALYZE,
                form
            );
            handleResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    const scanUrl = async (url) => {
        if (!url?.trim()) return;
        setLoading(true);
        setError(null);
        // Clean URL — strip fragment, add http if missing
        let clean = url.split('#')[0].trim();
        if (!clean.startsWith('http')) clean = 'http://' + clean;
        try {
            const { data } = await axios.post(
                API_ENDPOINTS.SCAN_URL,
                { url: clean },
                { headers: { 'Content-Type': 'application/json' } }
            );
            handleResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    const scanNetwork = async (target, scanType = 'full') => {
        if (!target?.trim()) return;
        setLoading(true);
        setError(null);
        try {
            const { data } = await axios.post(
                `${BACKEND}/scan_network`,
                { target: target.trim(), scan_type: scanType },
                { headers: { 'Content-Type': 'application/json' } }
            );
            handleResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        } finally {
            setLoading(false);
        }
    };

    return {
        findings,
        loading,
        error,
        total,
        analyzeConfig,
        analyzeFile,
        scanUrl,
        scanNetwork,
    };
};
