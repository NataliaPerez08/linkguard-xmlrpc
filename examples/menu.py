from ConfiguradorWireguardCliente import ConfiguradorWireguardCliente

def display_menu():
    """Display the main menu options."""
    print("\nWireGuard Client Configuration Menu")
    print("1. Generate WireGuard Keys")
    print("2. Create WireGuard Interface")
    print("3. Add Peer to Interface")
    print("4. Get Interface IP")
    print("5. Change Interface IP")
    print("6. Check Interface Status")
    print("7. Bring Interface Up")
    print("8. Bring Interface Down")
    print("9. Clear/Delete Interface")
    print("10. Exit")

def get_interface_name():
    """Prompt user for interface name with default."""
    default = ConfiguradorWireguardCliente.DEFAULT_INTERFACE
    name = input(f"Enter interface name [{default}]: ").strip()
    return name if name else default

def main():
    # Initialize with default interface name
    wg_config = ConfiguradorWireguardCliente()
    
    while True:
        display_menu()
        choice = input("Enter your choice (1-10): ").strip()
        
        try:
            if choice == "1":
                # Generate keys
                priv, pub = wg_config.create_keys()
                print(f"\nPrivate Key: {priv}")
                print(f"Public Key: {pub}")
                
            elif choice == "2":
                # Create interface
                interface_name = get_interface_name()
                wg_config = ConfiguradorWireguardCliente(interface_name)
                
                ip_wg = input("Enter interface IP with CIDR (e.g., 10.0.0.2/24): ").strip()
                
                # Optional peer configuration
                configure_peer = input("Configure peer now? (y/n): ").lower() == 'y'
                peer_params = {}
                if configure_peer:
                    peer_params['peer_public_key'] = input("Peer public key: ").strip()
                    allowed_ips = input("Allowed IPs (comma separated if multiple): ").strip()
                    peer_params['peer_allowed_ips'] = [ip.strip() for ip in allowed_ips.split(',')]
                    peer_params['peer_endpoint_ip'] = input("Peer endpoint IP: ").strip()
                    peer_params['peer_listen_port'] = int(input("Peer listen port: ").strip())
                
                success = wg_config.create_wg_interface(ip_wg, **peer_params)
                print(f"Interface creation {'succeeded' if success else 'failed or already exists'}")
                
            elif choice == "3":
                # Add peer
                if not wg_config._interface_exists():
                    print("Interface doesn't exist. Create it first.")
                    continue
                    
                pub_key = input("Peer public key: ").strip()
                allowed_ips = input("Allowed IPs (comma separated if multiple): ").strip()
                endpoint_ip = input("Peer endpoint IP: ").strip()
                listen_port = int(input("Peer listen port: ").strip())
                
                wg_config.add_peer(
                    public_key=pub_key,
                    allowed_ips=allowed_ips.split(','),
                    endpoint_ip=endpoint_ip,
                    listen_port=listen_port
                )
                print("Peer added successfully")
                
            elif choice == "4":
                # Get interface IP
                ip = wg_config.get_interface_ip()
                if ip:
                    print(f"Current interface IP: {ip}")
                else:
                    print("No IP assigned or interface doesn't exist")
                    
            elif choice == "5":
                # Change interface IP
                new_ip = input("Enter new IP with CIDR (e.g., 10.0.0.3/24): ").strip()
                wg_config.change_interface_ip(new_ip)
                print(f"Interface IP changed to {new_ip}")
                
            elif choice == "6":
                # Check interface status
                status = wg_config.get_interface_status()
                print(f"Interface status: {status}")
                
            elif choice == "7":
                # Bring interface up
                wg_config.up_interface()
                print("Interface brought up")
                
            elif choice == "8":
                # Bring interface down
                wg_config.down_interface()
                print("Interface brought down")
                
            elif choice == "9":
                # Clear interface
                if wg_config.clear_interface():
                    print("Interface cleared successfully")
                else:
                    print("Interface didn't exist")
                    
            elif choice == "10":
                print("Exiting...")
                break
                
            else:
                print("Invalid choice. Please enter a number between 1-10.")
                
        except Exception as e:
            print(f"\nError: {str(e)}")
            print("Please check your inputs and try again.")

if __name__ == "__main__":
    main()