echo "node_modules/" > .gitignore
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
echo ".DS_Store" >> .gitignore

# 1. Initialize Git in your folder
git init

# 2. Stage all files (respecting the .gitignore you just made)
git add .

# 3. Commit the files
git commit -m "Initial commit of FAPI 2.0 Security Demo"

# 4. Rename the branch to 'main'
git branch -M main

# 5. Link your local folder to your new GitHub repo
git remote add origin https://github.com/rbaronia/fapi-demo.git

# 6. Push the code up!
git push -u origin main