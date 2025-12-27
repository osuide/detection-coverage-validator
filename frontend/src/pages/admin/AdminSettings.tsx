import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Shield, Settings, CreditCard, Key, Eye, EyeOff,
  Save, AlertCircle, Check, ChevronLeft, RefreshCw,
  Lock, Globe, ToggleLeft, ToggleRight, Database, ExternalLink
} from 'lucide-react';
import { useAdminAuthStore, adminApi } from '../../stores/adminAuthStore';

interface Setting {
  key: string;
  value: string | null;
  is_secret: boolean;
  category: string;
  description: string | null;
  updated_at: string;
  is_configured: boolean;
}

interface StripeConfig {
  publishable_key: string | null;
  secret_key_configured: boolean;
  webhook_secret_configured: boolean;
}

export default function AdminSettings() {
  const navigate = useNavigate();
  const { isAuthenticated, isInitialised } = useAdminAuthStore();
  const [settings, setSettings] = useState<Setting[]>([]);
  const [stripeConfig, setStripeConfig] = useState<StripeConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [activeTab, setActiveTab] = useState<'billing' | 'auth' | 'features' | 'general' | 'data'>('billing');
  const [dataLoading, setDataLoading] = useState<string | null>(null);

  // Form state for Stripe
  const [stripeForm, setStripeForm] = useState({
    publishable_key: '',
    secret_key: '',
    webhook_secret: '',
  });
  const [showSecrets, setShowSecrets] = useState({
    secret_key: false,
    webhook_secret: false,
  });

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login');
    }
  }, [isAuthenticated, isInitialised, navigate]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchSettings();
    }
  }, [isAuthenticated]);

  const fetchSettings = async () => {
    try {
      const [settingsRes, stripeRes] = await Promise.all([
        adminApi.get('/settings').catch(() => null),
        adminApi.get('/settings/billing/stripe').catch(() => null),
      ]);

      if (settingsRes?.data) {
        setSettings(settingsRes.data.items);
      }

      if (stripeRes?.data) {
        setStripeConfig(stripeRes.data);
        setStripeForm(prev => ({
          ...prev,
          publishable_key: stripeRes.data.publishable_key || '',
        }));
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const saveStripeConfig = async () => {
    setSaving(true);
    setMessage(null);

    try {
      await adminApi.put('/settings/billing/stripe', {
        publishable_key: stripeForm.publishable_key || null,
        secret_key: stripeForm.secret_key || null,
        webhook_secret: stripeForm.webhook_secret || null,
        reason: 'Updated via Admin Portal',
      });

      setMessage({ type: 'success', text: 'Stripe configuration saved successfully' });
      // Clear secret fields after save
      setStripeForm(prev => ({
        ...prev,
        secret_key: '',
        webhook_secret: '',
      }));
      // Refresh data
      fetchSettings();
    } catch (error) {
      setMessage({ type: 'error', text: error instanceof Error ? error.message : 'Failed to save' });
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = async (key: string, value: string) => {
    try {
      await adminApi.put(`/settings/${key}`, { value, reason: 'Updated via Admin Portal' });
      setMessage({ type: 'success', text: `Setting "${key}" updated` });
      fetchSettings();
    } catch (error) {
      setMessage({ type: 'error', text: error instanceof Error ? error.message : 'Failed to update' });
    }
  };

  const toggleFeature = async (key: string, currentValue: string | null) => {
    const newValue = currentValue?.toLowerCase() === 'true' ? 'false' : 'true';
    await updateSetting(key, newValue);
  };

  const getSettingsByCategory = (category: string) => {
    return settings.filter(s => s.category === category);
  };

  /**
   * Format a cron expression into human-readable text.
   * E.g., "0 0 * * 0" -> "Weekly on Sunday at 00:00 UTC"
   */
  const formatCronExpression = (cron: string | null): string => {
    if (!cron) return '-';
    const parts = cron.split(' ');
    if (parts.length !== 5) return cron;

    const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;
    const time = `${hour.padStart(2, '0')}:${minute.padStart(2, '0')} UTC`;

    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

    // Weekly (specific day of week, any day of month)
    if (dayOfMonth === '*' && month === '*' && dayOfWeek !== '*') {
      const day = dayNames[parseInt(dayOfWeek)] || dayOfWeek;
      return `Weekly on ${day} at ${time}`;
    }

    // Monthly (specific day of month)
    if (dayOfMonth !== '*' && month === '*' && dayOfWeek === '*') {
      return `Monthly on day ${dayOfMonth} at ${time}`;
    }

    // Daily
    if (dayOfMonth === '*' && month === '*' && dayOfWeek === '*') {
      return `Daily at ${time}`;
    }

    // Fallback to raw expression
    return cron;
  };

  /**
   * Check if a setting is a MITRE sync setting.
   */
  const isMitreSyncSetting = (key: string): boolean => {
    return key === 'mitre_sync_enabled' || key === 'mitre_sync_cron';
  };

  const seedMitreData = async () => {
    setDataLoading('mitre');
    setMessage(null);
    try {
      const response = await adminApi.post('/settings/seed-mitre');
      setMessage({
        type: 'success',
        text: `MITRE data seeded: ${response.data.tactics_added} tactics, ${response.data.techniques_added} techniques added`
      });
    } catch (error) {
      setMessage({ type: 'error', text: error instanceof Error ? error.message : 'Failed to seed MITRE data' });
    } finally {
      setDataLoading(null);
    }
  };

  const seedComplianceData = async (forceReload: boolean = false) => {
    setDataLoading('compliance');
    setMessage(null);
    try {
      const response = await adminApi.post(`/settings/seed-compliance?force_reload=${forceReload}`);
      setMessage({
        type: 'success',
        text: `Compliance data ${forceReload ? 'reloaded' : 'seeded'}: ${response.data.frameworks_loaded} frameworks loaded, ${response.data.total_controls} controls, ${response.data.total_mappings} mappings`
      });
    } catch (error) {
      setMessage({ type: 'error', text: error instanceof Error ? error.message : 'Failed to seed compliance data' });
    } finally {
      setDataLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Top Nav */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <Link to="/admin/dashboard" className="text-gray-400 hover:text-white">
                <ChevronLeft className="w-5 h-5" />
              </Link>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <span className="text-white font-semibold">Platform Settings</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Message */}
        {message && (
          <div className={`mb-6 p-4 rounded-lg flex items-center gap-2 ${
            message.type === 'success' ? 'bg-green-900/50 border border-green-700 text-green-200' : 'bg-red-900/50 border border-red-700 text-red-200'
          }`}>
            {message.type === 'success' ? <Check className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
            <span>{message.text}</span>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-gray-700 overflow-x-auto">
          {[
            { id: 'billing', label: 'Billing', icon: CreditCard },
            { id: 'auth', label: 'Authentication', icon: Key },
            { id: 'features', label: 'Features', icon: ToggleRight },
            { id: 'general', label: 'General', icon: Settings },
            { id: 'data', label: 'Data', icon: Database },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
                activeTab === tab.id
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Billing Tab - Stripe Configuration */}
        {activeTab === 'billing' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-6">
              <CreditCard className="w-6 h-6 text-purple-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">Stripe Configuration</h2>
                <p className="text-sm text-gray-400">Configure your Stripe API keys for payment processing</p>
              </div>
            </div>

            {/* Status indicators */}
            {stripeConfig && (
              <div className="flex gap-4 mb-6 p-4 bg-gray-700/50 rounded-lg">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${stripeConfig.publishable_key ? 'bg-green-500' : 'bg-gray-500'}`}></div>
                  <span className="text-sm text-gray-300">Publishable Key</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${stripeConfig.secret_key_configured ? 'bg-green-500' : 'bg-gray-500'}`}></div>
                  <span className="text-sm text-gray-300">Secret Key</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${stripeConfig.webhook_secret_configured ? 'bg-green-500' : 'bg-gray-500'}`}></div>
                  <span className="text-sm text-gray-300">Webhook Secret</span>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {/* Publishable Key */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Publishable Key
                </label>
                <input
                  type="text"
                  value={stripeForm.publishable_key}
                  onChange={(e) => setStripeForm({ ...stripeForm, publishable_key: e.target.value })}
                  placeholder="pk_live_... or pk_test_..."
                  className="w-full px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                />
                <p className="text-xs text-gray-500 mt-1">This key is public and used in the frontend</p>
              </div>

              {/* Secret Key */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Secret Key {stripeConfig?.secret_key_configured && <span className="text-green-400">(configured)</span>}
                </label>
                <div className="relative">
                  <input
                    type={showSecrets.secret_key ? 'text' : 'password'}
                    value={stripeForm.secret_key}
                    onChange={(e) => setStripeForm({ ...stripeForm, secret_key: e.target.value })}
                    placeholder={stripeConfig?.secret_key_configured ? 'Leave blank to keep current' : 'sk_live_... or sk_test_...'}
                    className="w-full px-4 py-2.5 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecrets({ ...showSecrets, secret_key: !showSecrets.secret_key })}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                  >
                    {showSecrets.secret_key ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  <Lock className="w-3 h-3 inline mr-1" />
                  This key is encrypted at rest and never shown
                </p>
              </div>

              {/* Webhook Secret */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Webhook Secret {stripeConfig?.webhook_secret_configured && <span className="text-green-400">(configured)</span>}
                </label>
                <div className="relative">
                  <input
                    type={showSecrets.webhook_secret ? 'text' : 'password'}
                    value={stripeForm.webhook_secret}
                    onChange={(e) => setStripeForm({ ...stripeForm, webhook_secret: e.target.value })}
                    placeholder={stripeConfig?.webhook_secret_configured ? 'Leave blank to keep current' : 'whsec_...'}
                    className="w-full px-4 py-2.5 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecrets({ ...showSecrets, webhook_secret: !showSecrets.webhook_secret })}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                  >
                    {showSecrets.webhook_secret ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <button
                onClick={saveStripeConfig}
                disabled={saving}
                className="flex items-center gap-2 px-4 py-2.5 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Save Stripe Configuration
              </button>
            </div>
          </div>
        )}

        {/* Features Tab */}
        {activeTab === 'features' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-6">
              <ToggleRight className="w-6 h-6 text-green-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">Feature Flags</h2>
                <p className="text-sm text-gray-400">Enable or disable platform features</p>
              </div>
            </div>

            <div className="space-y-4">
              {getSettingsByCategory('feature').map(setting => (
                <div key={setting.key} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
                  <div>
                    <p className="text-white font-medium">{setting.key.replace('feature_', '').replace(/_/g, ' ')}</p>
                    <p className="text-sm text-gray-400">{setting.description}</p>
                  </div>
                  <button
                    onClick={() => toggleFeature(setting.key, setting.value)}
                    className={`p-2 rounded-lg transition-colors ${
                      setting.value?.toLowerCase() === 'true'
                        ? 'bg-green-600 text-white'
                        : 'bg-gray-600 text-gray-400'
                    }`}
                  >
                    {setting.value?.toLowerCase() === 'true' ? (
                      <ToggleRight className="w-6 h-6" />
                    ) : (
                      <ToggleLeft className="w-6 h-6" />
                    )}
                  </button>
                </div>
              ))}

              {getSettingsByCategory('feature').length === 0 && (
                <p className="text-gray-400 text-center py-4">No feature flags configured</p>
              )}
            </div>
          </div>
        )}

        {/* General Tab */}
        {activeTab === 'general' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-6">
              <Globe className="w-6 h-6 text-blue-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">General Settings</h2>
                <p className="text-sm text-gray-400">Platform-wide configuration</p>
              </div>
            </div>

            <div className="space-y-4">
              {getSettingsByCategory('general').map(setting => (
                <div key={setting.key} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex-1">
                    <p className="text-white font-medium">
                      {setting.key
                        .replace('platform_', '')
                        .replace('mitre_', 'MITRE ')
                        .replace(/_/g, ' ')}
                    </p>
                    <p className="text-sm text-gray-400">{setting.description}</p>
                    {/* Add link to MITRE Data page for MITRE sync settings */}
                    {isMitreSyncSetting(setting.key) && (
                      <Link
                        to="/admin/mitre"
                        className="inline-flex items-center gap-1 text-sm text-indigo-400 hover:text-indigo-300 mt-1"
                      >
                        Manage schedule
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    {setting.value === 'true' || setting.value === 'false' ? (
                      <button
                        onClick={() => toggleFeature(setting.key, setting.value)}
                        className={`p-2 rounded-lg transition-colors ${
                          setting.value === 'true'
                            ? 'bg-green-600 text-white'
                            : 'bg-gray-600 text-gray-400'
                        }`}
                      >
                        {setting.value === 'true' ? (
                          <ToggleRight className="w-6 h-6" />
                        ) : (
                          <ToggleLeft className="w-6 h-6" />
                        )}
                      </button>
                    ) : setting.key === 'mitre_sync_cron' ? (
                      <span className="text-gray-300">{formatCronExpression(setting.value)}</span>
                    ) : (
                      <span className="text-gray-300">{setting.value || '-'}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Auth Tab */}
        {activeTab === 'auth' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-6">
              <Key className="w-6 h-6 text-yellow-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">Authentication Settings</h2>
                <p className="text-sm text-gray-400">OAuth and SSO configuration</p>
              </div>
            </div>

            <div className="space-y-4">
              {getSettingsByCategory('auth').map(setting => (
                <div key={setting.key} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
                  <div>
                    <p className="text-white font-medium">{setting.key.replace(/_/g, ' ')}</p>
                    <p className="text-sm text-gray-400">{setting.description}</p>
                  </div>
                  <span className={`text-sm ${setting.is_configured ? 'text-green-400' : 'text-gray-500'}`}>
                    {setting.is_configured ? 'Configured' : 'Not set'}
                  </span>
                </div>
              ))}

              {getSettingsByCategory('auth').length === 0 && (
                <p className="text-gray-400 text-center py-4">
                  OAuth settings are managed through environment variables or AWS Cognito
                </p>
              )}
            </div>
          </div>
        )}

        {/* Data Management Tab */}
        {activeTab === 'data' && (
          <div className="space-y-6">
            {/* MITRE ATT&CK Data */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-center gap-3 mb-4">
                <Database className="w-6 h-6 text-red-400" />
                <div>
                  <h2 className="text-lg font-semibold text-white">MITRE ATT&CK Data</h2>
                  <p className="text-sm text-gray-400">Tactics and techniques from the MITRE ATT&CK framework</p>
                </div>
              </div>
              <p className="text-gray-300 text-sm mb-4">
                Seeds or updates MITRE ATT&CK tactics and techniques. New entries are added; existing entries are preserved.
              </p>
              <button
                onClick={seedMitreData}
                disabled={dataLoading !== null}
                className="flex items-center gap-2 px-4 py-2.5 bg-gray-700 text-white rounded-lg font-medium hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {dataLoading === 'mitre' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />}
                Seed MITRE Data
              </button>
            </div>

            {/* Compliance Frameworks Data */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-center gap-3 mb-4">
                <Shield className="w-6 h-6 text-blue-400" />
                <div>
                  <h2 className="text-lg font-semibold text-white">Compliance Frameworks</h2>
                  <p className="text-sm text-gray-400">CIS Controls v8 and NIST 800-53 mappings</p>
                </div>
              </div>
              <p className="text-gray-300 text-sm mb-4">
                Loads compliance framework controls and their mappings to MITRE ATT&CK techniques.
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => seedComplianceData(false)}
                  disabled={dataLoading !== null}
                  className="flex items-center gap-2 px-4 py-2.5 bg-gray-700 text-white rounded-lg font-medium hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {dataLoading === 'compliance' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />}
                  Seed Compliance Data
                </button>
                <button
                  onClick={() => seedComplianceData(true)}
                  disabled={dataLoading !== null}
                  className="flex items-center gap-2 px-4 py-2.5 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {dataLoading === 'compliance' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  Force Reload
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-3">
                <AlertCircle className="w-3 h-3 inline mr-1" />
                Force Reload will clear all existing compliance data and reload from source files. Use after updating mappings.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
