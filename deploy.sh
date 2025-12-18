#!/bin/bash
echo "========================================"
echo "    THREAT SCANNER DEPLOYMENT ASSISTANT"
echo "========================================"
echo ""
echo "This script will push your code to GitHub."
echo "You will be asked for your GitHub username and password."
echo "NOTE: If you have 2FA enabled, your 'password' must be a Personal Access Token."
echo ""
echo "Pushing code to: https://github.com/Decipher-ceo/threat-scanner.git"
echo "..."

git push -u origin master

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Success! Your code is on GitHub."
    echo "Now go to Render and Vercel to finish deployment."
else
    echo ""
    echo "❌ Push failed. Please check your credentials and try again."
fi
