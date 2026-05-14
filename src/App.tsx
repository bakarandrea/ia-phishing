import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, ShieldQuestion, 
  Search, Mail, Link as LinkIcon, FileUp, 
  History, Settings, Bell, Info, ChevronRight,
  AlertTriangle, CheckCircle2, XCircle, Loader2,
  Trash2, ExternalLink, LogOut, User as UserIcon,
  Shield, Fingerprint, Lock, Eye, EyeOff
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import ReactMarkdown from 'react-markdown';
import { cn } from './lib/utils';
import { scanContent, scanFile, type ScanResult } from './services/aiService';
import { authService, type User } from './services/authService';
import axios from 'axios';

// --- Types ---
interface HistoryItem {
  id: string;
  type: 'email' | 'url' | 'file';
  input: string;
  result: ScanResult;
  timestamp: number;
}

// --- Components ---

const RiskBadge = ({ level }: { level: ScanResult['riskLevel'] }) => {
  const styles = {
    SAFE: "bg-emerald-100 text-emerald-700 border-emerald-200",
    SUSPICIOUS: "bg-amber-100 text-amber-700 border-amber-200",
    PHISHING: "bg-rose-100 text-rose-700 border-rose-200"
  };

  const icons = {
    SAFE: <CheckCircle2 className="w-3 h-3" />,
    SUSPICIOUS: <AlertTriangle className="w-3 h-3" />,
    PHISHING: <XCircle className="w-3 h-3" />
  };

  return (
    <div className={cn("px-2 py-1 rounded-full text-[10px] font-bold border flex items-center gap-1 uppercase tracking-wider", styles[level])}>
      {icons[level]}
      {level}
    </div>
  );
};

const ResultCard = ({ result, onDismiss }: { result: ScanResult, onDismiss: () => void }) => {
  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="bg-white rounded-[2rem] p-6 shadow-2xl border border-slate-100 overflow-hidden relative"
    >
      <div className={cn(
        "absolute top-0 left-0 w-full h-1.5",
        result.riskLevel === 'SAFE' ? 'bg-emerald-500' : 
        result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-rose-500'
      )} />

      <div className="flex justify-between items-start mb-6">
        <div>
          <h3 className="text-xl font-bold text-slate-800 leading-tight mb-1">
            Analysis Report
          </h3>
          <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Engine Confidence: {result.score}%</p>
        </div>
        <RiskBadge level={result.riskLevel} />
      </div>

      <div className="space-y-4">
        <div className="bg-slate-50 rounded-2xl p-4 border border-slate-100">
          <p className="text-slate-600 leading-relaxed text-sm font-medium italic">
            "{result.explanation}"
          </p>
        </div>

        {result.threats.length > 0 && (
          <div>
            <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-3">Threat Indicators</h4>
            <div className="flex flex-wrap gap-2">
              {result.threats.map((threat, i) => (
                <span key={i} className="px-3 py-1 bg-slate-100 text-slate-600 rounded-lg text-[10px] font-bold border border-slate-200">
                  {threat}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className={cn(
          "p-4 rounded-2xl border flex items-start gap-4",
          result.riskLevel === 'SAFE' ? 'bg-emerald-50 border-emerald-100' : 
          result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-50 border-amber-100' : 'bg-rose-50 border-rose-100'
        )}>
          <div className={cn(
            "p-2 rounded-xl shrink-0 shadow-sm",
            result.riskLevel === 'SAFE' ? 'bg-emerald-500 text-white' : 
            result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-500 text-white' : 'bg-rose-500 text-white'
          )}>
            <Info className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-bold mb-1 text-slate-800">Recommendation</h4>
            <p className="text-[11px] text-slate-600 leading-relaxed font-medium">
              {result.recommendation}
            </p>
          </div>
        </div>
      </div>

      <button 
        onClick={onDismiss}
        className="w-full mt-8 py-3.5 bg-slate-900 text-white rounded-xl font-bold text-sm active:scale-95 transition-all shadow-lg shadow-slate-200"
      >
        Dismiss Report
      </button>
    </motion.div>
  );
};

const ArchitectureView = () => {
  const content = `
# PhishGuard AI Systems Implementation

## 🛡️ Backend Deliverables (Django + Gemini)
**Stack:** Python 3.10+, Django 4.2+, Django Rest Framework (DRF), PyJWT.

### 🐍 Django Directory Structure
\`\`\`text
phish_shield_backend/
├── manage.py
├── core/                  # Project Configuration
│   ├── settings.py        # SECRET_KEY & JWT Config
│   └── urls.py
├── api/                   # Main Application App
│   ├── views.py           # Gemini AI Proxy Logic
│   ├── models.py          # Scan History & Users
│   ├── serializers.py
│   └── services/
│       └── gemini_service.py # Google GenAI Integration
└── .env                   # Environment Secrets
\`\`\`

### 🔑 Secret Key Configuration
Add the following to your \`core/settings.py\` and \`.env\`:
\`\`\`python
# core/settings.py
import os
from datetime import timedelta

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'SIGNING_KEY': JWT_SECRET,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
\`\`\`

### 🤖 Gemini Service (Python)
\`\`\`python
# api/services/gemini_service.py
import google.generativeai as genai
from django.conf import settings

genai.configure(api_key=settings.GEMINI_API_KEY)

def analyze_content(content, content_type):
    model = genai.GenerativeModel('gemini-1.5-pro')
    prompt = f"Analyze this {content_type} for phishing indicators: {content}"
    response = model.generate_content(prompt)
    return response.text
\`\`\`

## 📱 Mobile Architecture (Kotlin/MVVM)
**Stack:** Kotlin, Retrofit, Jetpack Compose.

### 🏗️ Kotlin Structure
\`\`\`text
com.phishshield.app/
├── data/
│   ├── api/          # Retrofit Endpoints
│   ├── model/        # Analysis DTOs
│   └── repository/   # Data Source Management
├── ui/
│   ├── scanner/      # Scanner ViewModels
│   └── results/      # Analysis Display
└── domain/
    └── usecase/      # Business Logic
\`\`\`

## 🌐 Custom Backend & AI Integration
**Auth Strategy:** JWT-based session management.
**Status:** Live Preview runs an Express simulation of the Django logic.

## 🚀 Step-by-Step Development Plan
1. **Infrastructure:** Provision Django server with Postgres and Redis for rate limiting.
2. **Security:** Implement JWT auth and CSRF protection.
3. **AI Core:** Configure Gemini 1.5 Pro for multimodal analysis.
4. **Mobile:** Build Kotlin app with real-time push notifications for threat alerts.
`;

  return (
    <div className="space-y-6 pb-20">
      <div className="bg-white rounded-[2rem] p-6 shadow-sm border border-slate-100">
        <div className="prose prose-sm max-w-none prose-slate">
          <ReactMarkdown
            components={{
              h1: ({ children }) => <h1 className="text-lg font-black text-slate-800 mb-4">{children}</h1>,
              h2: ({ children }) => <h2 className="text-md font-bold text-slate-700 mt-6 mb-2">{children}</h2>,
              h3: ({ children }) => <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mt-4 mb-2">{children}</h3>,
              p: ({ children }) => <p className="text-slate-600 mb-4 font-medium leading-relaxed">{children}</p>,
              code: ({ children }) => <code className="bg-slate-50 text-indigo-600 px-1.5 py-0.5 rounded text-xs font-mono border border-slate-100">{children}</code>,
              pre: ({ children }) => <pre className="bg-slate-900 text-slate-200 p-4 rounded-xl text-xs overflow-x-auto mb-4 border border-slate-800">{children}</pre>,
              ul: ({ children }) => <ul className="list-disc pl-5 space-y-1 mb-4 text-slate-600 font-medium">{children}</ul>,
              li: ({ children }) => <li className="text-xs">{children}</li>
            }}
          >
            {content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
};

const AuthScreen = ({ onAuthSuccess }: { onAuthSuccess: (user: User) => void }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (isLogin) {
        const user = await authService.login(email, password);
        onAuthSuccess(user);
      } else {
        const user = await authService.register(email, password);
        onAuthSuccess(user);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] px-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-sm"
      >

        <div className="text-center mb-10">
          <div className="inline-flex p-4 bg-indigo-600 rounded-3xl shadow-xl shadow-indigo-100 mb-6 text-white">
            <Shield className="w-10 h-10" />
          </div>
          <h1 className="text-3xl font-black text-slate-900 tracking-tight mb-2">PhishGuard</h1>
          <p className="text-slate-500 font-medium text-sm">Enterprise-grade AI security for everyone.</p>
        </div>

        <form onSubmit={handleAuth} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
              <input 
                type="email" 
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full pl-12 pr-4 py-3.5 bg-white border border-slate-200 rounded-2xl focus:ring-4 focus:ring-indigo-100 focus:border-indigo-600 outline-none transition-all font-medium text-sm"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Password</label>
            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
              <input 
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-12 pr-12 py-3.5 bg-white border border-slate-200 rounded-2xl focus:ring-4 focus:ring-indigo-100 focus:border-indigo-600 outline-none transition-all font-medium text-sm"
              />
              <button 
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {error && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="p-3 bg-rose-50 border border-rose-100 rounded-xl flex items-center gap-2 text-rose-600 text-xs font-bold"
            >
              <AlertTriangle className="w-4 h-4" />
              {error}
            </motion.div>
          )}

          <button 
            type="submit"
            disabled={loading}
            className="w-full py-4 bg-indigo-600 text-white rounded-2xl font-bold text-sm shadow-xl shadow-indigo-100 hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : (isLogin ? "Sign In" : "Create Account")}
          </button>
        </form>

        <div className="mt-8 text-center">
          <button 
            onClick={() => setIsLogin(!isLogin)}
            className="text-sm font-bold text-slate-500 hover:text-indigo-600 transition-colors"
          >
            {isLogin ? "New here? Create an account" : "Already have an account? Sign in"}
          </button>
        </div>
      </motion.div>
    </div>
  );
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [activeTab, setActiveTab] = useState<'scan' | 'history' | 'docs'>('scan');
  const [scanType, setScanType] = useState<'email' | 'url' | 'file'>('url');
  const [inputValue, setInputValue] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const user = await authService.me();
        setUser(user);
      } catch (err) {
        console.warn('Auth check failed:', err);
      } finally {
        setAuthChecking(false);
      }
    };

    checkAuth();
  }, []);

  useEffect(() => {
    if (user) {
      const saved = localStorage.getItem(`ps_history_${user.id}`);
      setHistory(saved ? JSON.parse(saved) : []);
    }
  }, [user]);

  const saveToHistory = (result: ScanResult, type: any, input: string) => {
    if (!user) return;
    const newItem: HistoryItem = {
      id: Math.random().toString(36).substring(7),
      type,
      input: input.length > 50 ? input.substring(0, 50) + '...' : input,
      result,
      timestamp: Date.now()
    };
    const newHistory = [newItem, ...history].slice(0, 20);
    setHistory(newHistory);
    localStorage.setItem(`ps_history_${user.id}`, JSON.stringify(newHistory));
  };

  const handleScan = async () => {
    if (!inputValue && scanType !== 'file') return;
    setIsScanning(true);
    try {
      const result = await scanContent(inputValue, scanType as any);
      setScanResult(result);
      saveToHistory(result, scanType, inputValue);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsScanning(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const { data } = await axios.post('/api/scan/file', formData);
      const result = await scanFile(data);
      setScanResult(result);
      saveToHistory(result, 'file', file.name);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLogout = () => {
    authService.logout();
    setUser(null);
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-indigo-600 animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-50">
        <AuthScreen onAuthSuccess={setUser} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex justify-center p-0 sm:p-4 text-slate-900 font-sans">
      {/* Mobile Frame Simulation */}
      <div className="w-full max-w-[420px] bg-white sm:rounded-[3rem] shadow-2xl shadow-slate-200 overflow-hidden flex flex-col relative border-4 border-slate-100">
        
        {/* App Header */}
        <div className="px-6 pt-6 pb-4 flex justify-between items-center border-b border-slate-50">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600 rounded-xl text-white shadow-lg shadow-indigo-100">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-black tracking-tight text-slate-800">PhishGuard</h1>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Global Defense Active</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button className="p-2 bg-slate-50 rounded-xl text-slate-400 border border-slate-100">
               <Bell className="w-4 h-4" />
            </button>
            <button onClick={handleLogout} className="p-2 bg-rose-50 rounded-xl text-rose-500 border border-rose-100">
               <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto px-6 pt-6 pb-24 scrollbar-hide">
          <AnimatePresence mode="wait">
            {activeTab === 'scan' && (
              <motion.div 
                key="scan"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Hero Section */}
                <div className="bg-white rounded-[2rem] p-6 border border-slate-100 shadow-sm relative overflow-hidden">
                  <div className="relative z-10">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                      <span className="text-[10px] font-black text-emerald-600 uppercase tracking-widest">Real-time Analysis</span>
                    </div>
                    <h2 className="text-xl font-bold leading-tight mb-4 text-slate-800">Identify threats before they strike.</h2>
                    <div className="flex items-center gap-2 text-xs text-slate-400 font-medium">
                      <Fingerprint className="w-4 h-4" />
                      <span>End-to-End Threat Intelligence</span>
                    </div>
                  </div>
                  <ShieldAlert className="absolute -bottom-8 -right-8 w-40 h-40 text-slate-50 -rotate-12" />
                </div>

                {/* Scan Type Selector */}
                <div className="flex p-1.5 bg-slate-100 rounded-2xl">
                  {['url', 'email', 'file'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setScanType(type as any)}
                      className={cn(
                        "flex-1 py-3.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all",
                        scanType === type 
                          ? "bg-white text-indigo-600 shadow-sm border border-slate-200" 
                          : "text-slate-400 hover:text-slate-600"
                      )}
                    >
                      {type}
                    </button>
                  ))}
                </div>

                {/* Input Area */}
                <div className="space-y-4">
                  {scanType === 'file' ? (
                    <div 
                      onClick={() => fileInputRef.current?.click()}
                      className="border-2 border-dashed border-slate-200 rounded-[2rem] p-8 flex flex-col items-center justify-center bg-slate-50 hover:bg-slate-100/50 cursor-pointer transition-all active:scale-[0.98]"
                    >
                      <div className="p-4 bg-white rounded-2xl shadow-sm border border-slate-100 mb-4 text-indigo-600 transition-transform group-hover:scale-110">
                        <FileUp className="w-8 h-8" />
                      </div>
                      <p className="text-sm font-bold text-slate-800 mb-1">Click to Analyze File</p>
                      <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">PDF • TXT • Image</p>
                      <input 
                        type="file" 
                        ref={fileInputRef} 
                        className="hidden" 
                        onChange={handleFileUpload}
                      />
                    </div>
                  ) : (
                    <div className="relative">
                      <textarea
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder={scanType === 'url' ? 'https://suspicious-link.net' : 'Paste the email body or header here...'}
                        className="w-full h-44 p-6 rounded-[2rem] bg-slate-50 border border-slate-200 focus:bg-white focus:border-indigo-600 focus:ring-4 focus:ring-indigo-100 outline-none transition-all resize-none font-medium text-sm text-slate-700 leading-relaxed placeholder:text-slate-300"
                      />
                      <button 
                        onClick={handleScan}
                        disabled={isScanning || !inputValue}
                        className="absolute bottom-4 right-4 p-4 bg-slate-900 text-white rounded-2xl shadow-xl hover:bg-black disabled:opacity-30 active:scale-90 transition-all"
                      >
                        {isScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
                      </button>
                    </div>
                  )}
                </div>

                {/* Scanning Progress */}
                <AnimatePresence>
                  {isScanning && (
                    <motion.div 
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="fixed inset-0 z-50 bg-white/90 backdrop-blur-md flex flex-col items-center justify-center p-12"
                    >
                      <div className="relative mb-12">
                        <div className="w-28 h-28 rounded-full border-[2px] border-slate-100 border-t-indigo-600 animate-spin" />
                        <ShieldQuestion className="w-10 h-10 text-indigo-600 absolute inset-0 m-auto animate-pulse" />
                      </div>
                      <h3 className="text-xl font-black mb-2 text-center text-slate-900">Neural Scanning...</h3>
                      <p className="text-slate-400 text-center text-xs font-bold uppercase tracking-widest">
                        Evaluating Multi-Vector Threats
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>
                
                {/* Result Modal Overlay */}
                <AnimatePresence>
                  {scanResult && (
                    <motion.div 
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-[2px] flex items-end sm:items-center justify-center p-6"
                    >
                      <div className="w-full max-w-[380px]">
                        <ResultCard result={scanResult} onDismiss={() => setScanResult(null)} />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )}

            {activeTab === 'history' && (
              <motion.div 
                key="history"
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="space-y-4"
              >
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-black text-slate-800">Scan Logs</h2>
                  <button 
                    onClick={() => {
                        setHistory([]);
                        localStorage.removeItem(`ps_history_${user.id}`);
                    }}
                    className="p-2 text-rose-500 bg-rose-50 rounded-xl border border-rose-100 active:scale-95 transition-all"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>

                {history.length === 0 ? (
                  <div className="py-24 flex flex-col items-center justify-center text-slate-300">
                    <History className="w-16 h-16 mb-4 opacity-10" />
                    <p className="text-xs font-bold uppercase tracking-widest italic">No logged activity</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {history.map((item) => (
                      <div 
                        key={item.id}
                        onClick={() => setScanResult(item.result)}
                        className="bg-white rounded-3xl p-4 border border-slate-100 shadow-sm flex items-center gap-4 active:scale-[0.98] transition-all cursor-pointer group"
                      >
                        <div className={cn(
                          "p-4 rounded-2xl shrink-0 group-hover:scale-110 transition-transform",
                          item.result.riskLevel === 'SAFE' ? 'bg-emerald-50 text-emerald-600' : 
                          item.result.riskLevel === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-600' : 'bg-rose-50 text-rose-600'
                        )}>
                          {item.type === 'url' ? <LinkIcon className="w-4 h-4" /> : 
                           item.type === 'email' ? <Mail className="w-4 h-4" /> : <FileUp className="w-4 h-4" />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex justify-between items-center mb-1">
                            <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{item.type}</p>
                            <p className="text-[9px] text-slate-300 font-bold">{new Date(item.timestamp).toLocaleDateString()}</p>
                          </div>
                          <p className="text-sm font-bold truncate text-slate-800">{item.input}</p>
                        </div>
                        <ChevronRight className="w-4 h-4 text-slate-200" />
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'docs' && (
                <motion.div
                  key="docs"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                >
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-black text-slate-800">System Core</h2>
                    <a href="#" className="p-2 bg-slate-50 text-slate-400 rounded-xl border border-slate-100">
                        <Settings className="w-4 h-4" />
                    </a>
                  </div>
                  <ArchitectureView />
                </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Global Protection Footer */}
        <div className="px-6 py-3 bg-slate-900 border-t border-slate-800 flex justify-center">
            <div className="flex items-center gap-4 text-[9px] font-black uppercase tracking-[0.2em] text-slate-500">
                <span className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" /> Network SECURED</span>
                <span className="w-1 h-1 bg-slate-700 rounded-full" />
                <span>v3.1.0</span>
            </div>
        </div>

        {/* Bottom Tab Bar */}
        <div className="absolute bottom-6 left-6 right-6 bg-white/80 backdrop-blur-lg rounded-[2rem] h-20 px-6 flex items-center justify-between shadow-2xl shadow-slate-200 border border-slate-100">
          {[
            { id: 'scan', icon: Search, label: 'Safety' },
            { id: 'history', icon: History, label: 'Logs' },
            { id: 'docs', icon: Fingerprint, label: 'Tech' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={cn(
                "flex flex-col items-center justify-center flex-1 transition-all relative py-2",
                activeTab === tab.id ? "text-indigo-600" : "text-slate-300 hover:text-slate-400"
              )}
            >
              <tab.icon className={cn("w-6 h-6 mb-1", activeTab === tab.id ? "scale-110" : "scale-100")} />
              <span className="text-[9px] font-black uppercase tracking-widest">{tab.label}</span>
              {activeTab === tab.id && (
                <motion.div layoutId="activeTabPill" className="absolute -bottom-2 w-5 h-1 bg-indigo-600 rounded-full" />
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
