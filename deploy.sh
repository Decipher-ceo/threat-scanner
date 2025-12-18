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

# Stage and commit all changes
echo "Step 1: Staging and committing changes..."
git add .
git commit -m "Deployment update: Fix routing and assets" || echo "No new changes to commit"

# Detect current branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "Step 2: Pushing to GitHub (branch: $BRANCH)..."
git push -u origin $BRANCH

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Success! Your code is updated on GitHub."
    echo "Vercel will now automatically rebuild. Give it 30 seconds, then reload."
else
    echo ""
    echo "❌ Push failed. Please check your credentials and try again."
fi
