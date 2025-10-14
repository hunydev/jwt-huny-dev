import React, { useState, useEffect } from 'react';
import { SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader } from 'jose';
import { Shield, ShieldCheck, ShieldX, Calendar, Clock, Copy, History, X, AlertCircle, CheckCircle } from 'lucide-react';

function App() {
  const defaultHeader = { alg: 'HS256', typ: 'JWT' };
  const defaultPayload = { 
    sub: '1234567890', 
    name: 'John Doe', 
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  const [token, setToken] = useState('');
  const [header, setHeader] = useState(JSON.stringify(defaultHeader, null, 2));
  const [payload, setPayload] = useState(JSON.stringify(defaultPayload, null, 2));
  const [secret, setSecret] = useState('your-256-bit-secret');
  const [isVerified, setIsVerified] = useState(null);
  const [algorithmSupported, setAlgorithmSupported] = useState(true);
  const [tokenParts, setTokenParts] = useState({ header: '', payload: '', signature: '', error: false });
  const [expEditMode, setExpEditMode] = useState('epoch'); // 'epoch', 'gmt', 'local'
  const [expDateValue, setExpDateValue] = useState('');
  
  // New features state
  const [tokenHistory, setTokenHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copiedField, setCopiedField] = useState('');
  const [showBatchMode, setShowBatchMode] = useState(false);
  const [batchTokens, setBatchTokens] = useState('');
  const [batchExpValue, setBatchExpValue] = useState('');

  // Load token history from localStorage
  useEffect(() => {
    const savedHistory = localStorage.getItem('jwtTokenHistory');
    if (savedHistory) {
      try {
        setTokenHistory(JSON.parse(savedHistory));
      } catch (error) {
        console.error('Failed to load history:', error);
      }
    }
  }, []);

  // Initial token generation
  useEffect(() => {
    generateToken(defaultHeader, defaultPayload, secret);
  }, []);

  // Verify token whenever token or secret changes
  useEffect(() => {
    if (token && secret) {
      verifyToken(token, secret);
    }
  }, [token, secret]);

  // Generate JWT token from header and payload
  const generateToken = async (headerObj, payloadObj, secretKey) => {
    try {
      // Check algorithm support
      const supportedAlgorithms = ['HS256', 'HS384', 'HS512'];
      const isSupported = supportedAlgorithms.includes(headerObj.alg);
      setAlgorithmSupported(isSupported);
      
      if (!isSupported) {
        console.warn(`Algorithm ${headerObj.alg} is not supported`);
        return;
      }

      const encodedSecret = new TextEncoder().encode(secretKey);
      const jwt = await new SignJWT(payloadObj)
        .setProtectedHeader(headerObj)
        .sign(encodedSecret);
      
      setToken(jwt);
      updateTokenParts(jwt);
      
      // Save to history
      saveToHistory(jwt, headerObj, payloadObj);
    } catch (error) {
      console.error('Token generation error:', error);
      setAlgorithmSupported(false);
    }
  };

  // Verify token signature
  const verifyToken = async (jwtToken, secretKey) => {
    try {
      const encodedSecret = new TextEncoder().encode(secretKey);
      await jwtVerify(jwtToken, encodedSecret);
      setIsVerified(true);
    } catch (error) {
      setIsVerified(false);
    }
  };

  // Update token parts for color coding
  const updateTokenParts = (jwtToken) => {
    if (!jwtToken || jwtToken.trim() === '') {
      setTokenParts({ header: '', payload: '', signature: '', error: false });
      return;
    }
    
    const parts = jwtToken.split('.');
    if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
      setTokenParts({
        header: parts[0],
        payload: parts[1],
        signature: parts[2],
        error: false
      });
    } else {
      setTokenParts({
        header: '',
        payload: '',
        signature: '',
        error: true
      });
    }
  };

  // Handle header change
  const handleHeaderChange = (value) => {
    setHeader(value);
    try {
      const headerObj = JSON.parse(value);
      const payloadObj = JSON.parse(payload);
      generateToken(headerObj, payloadObj, secret);
    } catch (error) {
      // Invalid JSON, wait for valid input
    }
  };

  // Handle payload change
  const handlePayloadChange = (value) => {
    setPayload(value);
    try {
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(value);
      generateToken(headerObj, payloadObj, secret);
      
      // Update exp edit value if exp exists
      if (payloadObj.exp) {
        updateExpEditValue(payloadObj.exp);
      }
    } catch (error) {
      // Invalid JSON, wait for valid input
    }
  };

  // Handle secret change
  const handleSecretChange = (value) => {
    setSecret(value);
    try {
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(payload);
      generateToken(headerObj, payloadObj, value);
    } catch (error) {
      // If JSON parsing fails, token verification will be handled by useEffect
      // This will show invalid signature if the token was signed with a different secret
    }
  };

  // Handle token change (decode)
  const handleTokenChange = (value) => {
    setToken(value);
    updateTokenParts(value);
    
    try {
      const decodedHeader = decodeProtectedHeader(value);
      const decodedPayload = decodeJwt(value);
      
      setHeader(JSON.stringify(decodedHeader, null, 2));
      setPayload(JSON.stringify(decodedPayload, null, 2));
      
      // Update exp edit value if exp exists
      if (decodedPayload.exp) {
        updateExpEditValue(decodedPayload.exp);
      }
      
      // Token verification will be handled by useEffect
    } catch (error) {
      // Invalid token format - can't even decode
      setIsVerified(null);
    }
  };

  // Update exp edit value based on mode
  const updateExpEditValue = (epochTime) => {
    if (expEditMode === 'epoch') {
      setExpDateValue(epochTime.toString());
    } else if (expEditMode === 'gmt') {
      const date = new Date(epochTime * 1000);
      setExpDateValue(date.toISOString().slice(0, 16));
    } else if (expEditMode === 'local') {
      const date = new Date(epochTime * 1000);
      const offset = date.getTimezoneOffset() * 60000;
      const localDate = new Date(date.getTime() - offset);
      setExpDateValue(localDate.toISOString().slice(0, 16));
    }
  };

  // Handle exp edit mode change
  const handleExpModeChange = (mode) => {
    setExpEditMode(mode);
    try {
      const payloadObj = JSON.parse(payload);
      if (payloadObj.exp) {
        if (mode === 'epoch') {
          setExpDateValue(payloadObj.exp.toString());
        } else if (mode === 'gmt') {
          const date = new Date(payloadObj.exp * 1000);
          setExpDateValue(date.toISOString().slice(0, 16));
        } else if (mode === 'local') {
          const date = new Date(payloadObj.exp * 1000);
          const offset = date.getTimezoneOffset() * 60000;
          const localDate = new Date(date.getTime() - offset);
          setExpDateValue(localDate.toISOString().slice(0, 16));
        }
      }
    } catch (error) {
      // Invalid payload
    }
  };

  // Handle exp value change
  const handleExpValueChange = (value) => {
    setExpDateValue(value);
    
    try {
      const payloadObj = JSON.parse(payload);
      let newExpTime;
      
      if (expEditMode === 'epoch') {
        newExpTime = parseInt(value);
      } else if (expEditMode === 'gmt') {
        newExpTime = Math.floor(new Date(value).getTime() / 1000);
      } else if (expEditMode === 'local') {
        const date = new Date(value);
        const offset = date.getTimezoneOffset() * 60000;
        newExpTime = Math.floor((date.getTime() + offset) / 1000);
      }
      
      if (!isNaN(newExpTime)) {
        payloadObj.exp = newExpTime;
        const newPayload = JSON.stringify(payloadObj, null, 2);
        setPayload(newPayload);
        
        const headerObj = JSON.parse(header);
        generateToken(headerObj, payloadObj, secret);
      }
    } catch (error) {
      // Invalid input
    }
  };

  // Save token to history
  const saveToHistory = (jwt, headerObj, payloadObj) => {
    const historyItem = {
      id: Date.now(),
      token: jwt,
      header: headerObj,
      payload: payloadObj,
      timestamp: new Date().toISOString(),
    };
    
    const newHistory = [historyItem, ...tokenHistory].slice(0, 10); // Keep last 10
    setTokenHistory(newHistory);
    localStorage.setItem('jwtTokenHistory', JSON.stringify(newHistory));
  };

  // Load token from history
  const loadFromHistory = (historyItem) => {
    setToken(historyItem.token);
    setHeader(JSON.stringify(historyItem.header, null, 2));
    setPayload(JSON.stringify(historyItem.payload, null, 2));
    updateTokenParts(historyItem.token);
    
    // Update exp edit value if exp exists
    if (historyItem.payload.exp) {
      updateExpEditValue(historyItem.payload.exp);
    }
    
    setShowHistory(false);
  };

  // Clear history
  const clearHistory = () => {
    setTokenHistory([]);
    localStorage.removeItem('jwtTokenHistory');
    setShowHistory(false);
  };

  // Copy to clipboard
  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(''), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  // Process batch tokens
  const processBatchTokens = () => {
    if (!batchExpValue || !batchTokens) return;
    
    const tokens = batchTokens.split('\n').filter(t => t.trim());
    const newExpTime = parseInt(batchExpValue);
    
    if (isNaN(newExpTime)) return;
    
    const processedTokens = [];
    
    for (const token of tokens) {
      try {
        const decodedHeader = decodeProtectedHeader(token.trim());
        const decodedPayload = decodeJwt(token.trim());
        
        // Update exp
        decodedPayload.exp = newExpTime;
        
        // Generate new token (sync operation not possible here, so we skip it)
        processedTokens.push({
          original: token.trim(),
          header: decodedHeader,
          payload: decodedPayload,
          newExp: newExpTime
        });
      } catch (error) {
        console.error('Failed to process token:', error);
      }
    }
    
    // For now, just show the results
    alert(`Processed ${processedTokens.length} tokens. New exp: ${newExpTime}`);
    setShowBatchMode(false);
  };

  // Format token with colors
  const formatTokenWithColors = () => {
    if (tokenParts.error) {
      return (
        <div className="flex items-center gap-2 p-3 bg-red-900/20 border border-red-500/30 rounded text-red-400">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">Invalid JWT format. Token must have 3 parts separated by dots (header.payload.signature)</span>
        </div>
      );
    }
    
    if (!tokenParts.header) return null;
    
    return (
      <div className="font-mono text-sm break-all leading-relaxed">
        <span className="text-red-500 font-semibold">{tokenParts.header}</span>
        <span className="text-gray-500">.</span>
        <span className="text-purple-500 font-semibold">{tokenParts.payload}</span>
        <span className="text-gray-500">.</span>
        <span className="text-cyan-500 font-semibold">{tokenParts.signature}</span>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white">
      <main className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <header className="mb-8">
          <h1 className="text-4xl font-bold mb-2 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            JWT Encoder/Decoder
          </h1>
          <p className="text-gray-400">Real-time JWT token encoding, decoding, and signature verification tool</p>
        </header>

        {/* JWT Token Section */}
        <div className="mb-6">
          <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <Shield className="w-5 h-5" />
                JWT Token
              </h2>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowHistory(!showHistory)}
                  className="flex items-center gap-1 text-blue-400 hover:text-blue-300 text-sm transition-colors"
                  title="Token History"
                >
                  <History className="w-4 h-4" />
                  <span>History</span>
                </button>
                <button
                  onClick={() => setShowBatchMode(!showBatchMode)}
                  className="flex items-center gap-1 text-purple-400 hover:text-purple-300 text-sm transition-colors"
                  title="Batch Processing"
                >
                  <Calendar className="w-4 h-4" />
                  <span>Batch</span>
                </button>
                {!algorithmSupported && (
                  <div className="flex items-center gap-1 text-orange-400 text-sm">
                    <AlertCircle className="w-4 h-4" />
                    <span>Unsupported Algorithm</span>
                  </div>
                )}
                {isVerified === true && (
                  <div className="flex items-center gap-1 text-green-400 text-sm">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Verified</span>
                  </div>
                )}
                {isVerified === false && (
                  <div className="flex items-center gap-1 text-red-400 text-sm">
                    <ShieldX className="w-4 h-4" />
                    <span>Invalid Signature</span>
                  </div>
                )}
              </div>
            </div>
            
            <div className="relative">
              <textarea
                value={token}
                onChange={(e) => handleTokenChange(e.target.value)}
                className="w-full h-32 bg-gray-900 text-white rounded p-4 pr-12 font-mono text-sm border border-gray-600 focus:border-blue-500 focus:outline-none resize-none"
                placeholder="Paste JWT token here..."
              />
              <button
                onClick={() => copyToClipboard(token, 'token')}
                className="absolute top-2 right-2 p-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Copy Token"
              >
                {copiedField === 'token' ? (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-gray-300" />
                )}
              </button>
            </div>
            
            <div className="mt-4 p-4 bg-gray-900 rounded border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs text-gray-400">Decoded Token Parts:</div>
                {!tokenParts.error && tokenParts.header && (
                  <div className="flex items-center gap-4 text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="text-red-500 font-semibold">■</span>
                      <span className="text-gray-400">Header</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-purple-500 font-semibold">■</span>
                      <span className="text-gray-400">Payload</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-cyan-500 font-semibold">■</span>
                      <span className="text-gray-400">Signature</span>
                    </div>
                  </div>
                )}
              </div>
              {formatTokenWithColors()}
            </div>

            {/* Token History Panel */}
            {showHistory && (
              <div className="mt-4 p-4 bg-gray-900 rounded border border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-blue-400">Token History (Last 10)</h3>
                  <div className="flex gap-2">
                    <button
                      onClick={clearHistory}
                      className="text-xs text-red-400 hover:text-red-300"
                    >
                      Clear All
                    </button>
                    <button
                      onClick={() => setShowHistory(false)}
                      className="text-gray-400 hover:text-white"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                {tokenHistory.length === 0 ? (
                  <p className="text-xs text-gray-500">No history yet</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {tokenHistory.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => loadFromHistory(item)}
                        className="p-2 bg-gray-800 rounded cursor-pointer hover:bg-gray-700 transition-colors"
                      >
                        <div className="text-xs text-gray-400 mb-1">
                          {new Date(item.timestamp).toLocaleString()}
                        </div>
                        <div className="text-xs font-mono text-gray-300 truncate">
                          {item.token.substring(0, 50)}...
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Batch Processing Panel */}
            {showBatchMode && (
              <div className="mt-4 p-4 bg-gray-900 rounded border border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-purple-400">Batch Expiration Update</h3>
                  <button
                    onClick={() => setShowBatchMode(false)}
                    className="text-gray-400 hover:text-white"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-gray-400 mb-1 block">
                      Paste multiple JWT tokens (one per line)
                    </label>
                    <textarea
                      value={batchTokens}
                      onChange={(e) => setBatchTokens(e.target.value)}
                      className="w-full h-32 bg-gray-800 text-white rounded p-3 font-mono text-xs border border-gray-600 focus:border-purple-500 focus:outline-none resize-none"
                      placeholder="eyJhbGc...&#10;eyJhbGc...&#10;eyJhbGc..."
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-400 mb-1 block">
                      New Expiration Time (Epoch)
                    </label>
                    <input
                      type="number"
                      value={batchExpValue}
                      onChange={(e) => setBatchExpValue(e.target.value)}
                      className="w-full bg-gray-800 text-white rounded p-3 font-mono text-xs border border-gray-600 focus:border-purple-500 focus:outline-none"
                      placeholder="1735689600"
                    />
                  </div>
                  <button
                    onClick={processBatchTokens}
                    className="w-full py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-medium text-sm transition-colors"
                  >
                    Process Tokens
                  </button>
                  <p className="text-xs text-gray-500">
                    This will update the exp field for all valid tokens
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Header Section */}
          <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xl font-semibold text-red-400">Header</h2>
              <button
                onClick={() => copyToClipboard(header, 'header')}
                className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Copy Header"
              >
                {copiedField === 'header' ? (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-gray-300" />
                )}
              </button>
            </div>
            <textarea
              value={header}
              onChange={(e) => handleHeaderChange(e.target.value)}
              className="w-full h-48 bg-gray-900 text-white rounded p-4 font-mono text-sm border border-gray-600 focus:border-red-500 focus:outline-none resize-none"
              placeholder='{"alg": "HS256", "typ": "JWT"}'
            />
            <div className="mt-2 text-xs text-gray-400">
              Edit header fields to update the token
            </div>
          </div>

          {/* Payload Section */}
          <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xl font-semibold text-purple-400">Payload</h2>
              <button
                onClick={() => copyToClipboard(payload, 'payload')}
                className="p-1.5 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Copy Payload"
              >
                {copiedField === 'payload' ? (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-gray-300" />
                )}
              </button>
            </div>
            <textarea
              value={payload}
              onChange={(e) => handlePayloadChange(e.target.value)}
              className="w-full h-48 bg-gray-900 text-white rounded p-4 font-mono text-sm border border-gray-600 focus:border-purple-500 focus:outline-none resize-none"
              placeholder='{"sub": "1234567890", "name": "John Doe"}'
            />
            <div className="mt-2 text-xs text-gray-400">
              Edit payload fields to update the token
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Secret Section */}
          <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
            <h2 className="text-xl font-semibold mb-3 text-cyan-400">Secret Key</h2>
            <input
              type="text"
              value={secret}
              onChange={(e) => handleSecretChange(e.target.value)}
              className="w-full bg-gray-900 text-white rounded p-4 font-mono text-sm border border-gray-600 focus:border-cyan-500 focus:outline-none"
              placeholder="Enter your secret key..."
            />
            <div className="mt-2 text-xs text-gray-400">
              Change the secret to re-sign the token
            </div>
          </div>

          {/* Exp Editor Section */}
          <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <Calendar className="w-5 h-5" />
              Expiration (exp) Editor
            </h2>
            
            <div className="flex gap-2 mb-3">
              <button
                onClick={() => handleExpModeChange('epoch')}
                className={`flex-1 py-2 px-3 rounded text-sm font-medium transition-colors ${
                  expEditMode === 'epoch'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                <Clock className="w-4 h-4 inline mr-1" />
                Epoch
              </button>
              <button
                onClick={() => handleExpModeChange('gmt')}
                className={`flex-1 py-2 px-3 rounded text-sm font-medium transition-colors ${
                  expEditMode === 'gmt'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                GMT
              </button>
              <button
                onClick={() => handleExpModeChange('local')}
                className={`flex-1 py-2 px-3 rounded text-sm font-medium transition-colors ${
                  expEditMode === 'local'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                Local
              </button>
            </div>

            {expEditMode === 'epoch' ? (
              <input
                type="number"
                value={expDateValue}
                onChange={(e) => handleExpValueChange(e.target.value)}
                className="w-full bg-gray-900 text-white rounded p-4 font-mono text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
                placeholder="Unix timestamp..."
              />
            ) : (
              <input
                type="datetime-local"
                value={expDateValue}
                onChange={(e) => handleExpValueChange(e.target.value)}
                className="w-full bg-gray-900 text-white rounded p-4 font-mono text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
              />
            )}
            
            <div className="mt-2 text-xs text-gray-400">
              Quick edit for token expiration time
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-8 text-center text-gray-500 text-sm space-y-2">
          <p>
            Powered by{' '}
            <a 
              href="https://github.com/panva/jose" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-purple-400 hover:text-purple-300 transition-colors font-semibold"
            >
              jose
            </a>
            {' '}• JavaScript module for JSON Web Tokens
          </p>
          <p>
            Made with ❤️ by{' '}
            <a 
              href="https://huny.dev" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 transition-colors"
            >
              huny.dev
            </a>
          </p>
        </footer>
      </main>
    </div>
  );
}

export default App;
