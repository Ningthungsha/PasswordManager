import json
import os
import re
from cryptography.fernet import Fernet
from getpass import getpass
from datetime import datetime

class PasswordManager:
    def __init__(self, filename="passwords.json", key_file="key.key"):
        self.filename = filename
        self.key_file = key_file
        self.cipher = None
        self.load_or_create_key()
        
    def load_or_create_key(self):
        """Load existing encryption key or create a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print("🔐 New encryption key created!")
        
        self.cipher = Fernet(key)
    
    def encrypt_password(self, password):
        """Encrypt a password"""
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        return self.cipher.decrypt(encrypted_password.encode()).decode()
    
    def check_password_strength(self, password):
        """
        Check password strength and return score + feedback
        Returns: (strength_level, score, feedback)
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("⚠️  Consider using 12+ characters for extra security")
        
        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("❌ Add uppercase letters (A-Z)")
        
        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("❌ Add lowercase letters (a-z)")
        
        # Numbers check
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("❌ Add numbers (0-9)")
        
        # Special characters check
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 1
        else:
            feedback.append("❌ Add special characters (!@#$%^&* etc.)")
        
        # Determine strength level
        if score >= 6:
            strength = "🟢 STRONG"
        elif score >= 4:
            strength = "🟡 MODERATE"
        else:
            strength = "🔴 WEAK"
        
        return strength, score, feedback
    
    def save_password(self, service, username, password):
        """Save a password with encryption"""
        # Check password strength
        strength, score, feedback = self.check_password_strength(password)
        
        print(f"\n📊 Password Strength: {strength} ({score}/6)")
        if feedback:
            for msg in feedback:
                print(f"  {msg}")
        
        confirm = input(f"\nDo you want to save this password? (yes/no): ").lower()
        if confirm != 'yes':
            print("❌ Password not saved.")
            return
        
        # Load existing passwords
        passwords = self.load_passwords()
        
        # Encrypt and store
        encrypted = self.encrypt_password(password)
        passwords[service] = {
            'username': username,
            'password': encrypted,
            'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save to file
        with open(self.filename, 'w') as f:
            json.dump(passwords, f, indent=4)
        
        print(f"✅ Password for '{service}' saved successfully!")
    
    def load_passwords(self):
        """Load all passwords from file"""
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                return json.load(f)
        return {}
    
    def get_password(self, service):
        """Retrieve and decrypt a password"""
        passwords = self.load_passwords()
        
        if service not in passwords:
            print(f"❌ No password found for '{service}'")
            return
        
        data = passwords[service]
        decrypted = self.decrypt_password(data['password'])
        
        print(f"\n🔓 Service: {service}")
        print(f"   Username: {data['username']}")
        print(f"   Password: {decrypted}")
        print(f"   Created: {data['created']}")
    
    def list_services(self):
        """List all saved services"""
        passwords = self.load_passwords()
        
        if not passwords:
            print("📭 No passwords saved yet!")
            return
        
        print("\n📋 Saved Services:")
        print("-" * 40)
        for i, service in enumerate(passwords.keys(), 1):
            created = passwords[service]['created']
            print(f"{i}. {service} (Created: {created})")
        print("-" * 40)
    
    def delete_password(self, service):
        """Delete a saved password"""
        passwords = self.load_passwords()
        
        if service not in passwords:
            print(f"❌ No password found for '{service}'")
            return
        
        confirm = input(f"⚠️  Delete password for '{service}'? (yes/no): ").lower()
        if confirm == 'yes':
            del passwords[service]
            with open(self.filename, 'w') as f:
                json.dump(passwords, f, indent=4)
            print(f"✅ Password for '{service}' deleted!")
        else:
            print("❌ Deletion cancelled.")
    
    def update_password(self, service):
        """Update an existing password"""
        passwords = self.load_passwords()
        
        if service not in passwords:
            print(f"❌ No password found for '{service}'")
            return
        
        new_password = getpass("Enter new password: ")
        strength, score, feedback = self.check_password_strength(new_password)
        
        print(f"\n📊 New Password Strength: {strength} ({score}/6)")
        if feedback:
            for msg in feedback:
                print(f"  {msg}")
        
        confirm = input("\nConfirm update? (yes/no): ").lower()
        if confirm == 'yes':
            encrypted = self.encrypt_password(new_password)
            passwords[service]['password'] = encrypted
            passwords[service]['created'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(self.filename, 'w') as f:
                json.dump(passwords, f, indent=4)
            print(f"✅ Password for '{service}' updated!")
        else:
            print("❌ Update cancelled.")

def main():
    print("=" * 50)
    print("🔐 SECURE PASSWORD MANAGER")
    print("=" * 50)
    
    pm = PasswordManager()
    
    while True:
        print("\n📌 MENU:")
        print("1. Save a new password")
        print("2. Get a password")
        print("3. List all services")
        print("4. Update a password")
        print("5. Delete a password")
        print("6. Exit")
        
        choice = input("\nChoose an option (1-6): ").strip()
        
        if choice == '1':
            service = input("Enter service name (e.g., Gmail, GitHub): ").strip()
            username = input("Enter username/email: ").strip()
            password = getpass("Enter password: ")
            pm.save_password(service, username, password)
        
        elif choice == '2':
            service = input("Enter service name: ").strip()
            pm.get_password(service)
        
        elif choice == '3':
            pm.list_services()
        
        elif choice == '4':
            service = input("Enter service name: ").strip()
            pm.update_password(service)
        
        elif choice == '5':
            service = input("Enter service name: ").strip()
            pm.delete_password(service)
        
        elif choice == '6':
            print("\n👋 Goodbye! Stay secure!")
            break
        
        else:
            print("❌ Invalid option. Try again.")

if __name__ == "__main__":
    main()