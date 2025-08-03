# Vercel Deployment Guide

## 🚀 Deploy to Vercel

Your IDS scanner is now configured for Vercel deployment!

### 📋 What's Included:
- ✅ Web Dashboard
- ✅ File Upload & Scanning
- ✅ Encryption/Decryption Tools
- ✅ User Management
- ✅ Admin Panel
- ⚠️ Network Monitoring (Disabled - requires privileged access)

### 🔧 Deployment Steps:

1. **Connect to Vercel:**
   - Go to [vercel.com](https://vercel.com)
   - Sign up/Login with GitHub
   - Click "New Project"
   - Import your repository: `ids-encryption-file-scanner`

2. **Configure Build Settings:**
   - **Framework Preset**: Other
   - **Build Command**: `pip install -r requirements_vercel.txt`
   - **Output Directory**: Leave empty
   - **Install Command**: `pip install -r requirements_vercel.txt`

3. **Environment Variables (Optional):**
   - `FLASK_ENV`: `production`
   - `SECRET_KEY`: Generate a random string

4. **Deploy:**
   - Click "Deploy"
   - Wait for build to complete
   - Your app will be live at: `https://your-app-name.vercel.app`

### 🌐 Features Available on Vercel:

#### ✅ Working Features:
- **Web Dashboard**: Real-time threat visualization
- **File Scanning**: Upload and scan files for threats
- **Encryption Tools**: Secure file encryption/decryption
- **User Management**: Login, signup, admin panel
- **Threat Logs**: View historical alerts
- **Model Metrics**: ML model performance analytics

#### ⚠️ Limited Features:
- **Network Monitoring**: Disabled (requires system privileges)
- **Real-time Packet Capture**: Not available on serverless
- **File System Operations**: Limited to temporary storage

### 🔄 Local vs Vercel:

| Feature | Local | Vercel |
|---------|-------|--------|
| Network Monitoring | ✅ Full | ❌ Disabled |
| File Scanning | ✅ Full | ✅ Full |
| Encryption | ✅ Full | ✅ Full |
| Dashboard | ✅ Full | ✅ Full |
| Real-time Alerts | ✅ Full | ⚠️ Limited |

### 🛠️ Customization:

To enable more features, consider:
- **Railway**: Better for full-stack apps
- **Heroku**: Good for Python apps
- **AWS/GCP**: Full server control
- **DigitalOcean**: VPS with full access

### 📊 Monitoring:

Your Vercel deployment will show:
- Build logs
- Function execution times
- Error rates
- Performance metrics

### 🔗 Quick Deploy:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Isaac-ek/ids-encryption-file-scanner)

Click the button above for one-click deployment! 