#include <gtk/gtk.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

GtkWidget *message_entry;
GtkWidget *encrypt_button;
GtkWidget *decrypt_button;
GtkWidget *reload_button;
GtkWidget *about_button;
GtkWidget *generate_keys_button; // New button for generating keys
EVP_PKEY *loaded_public_key=NULL;
EVP_PKEY *loaded_private_key=NULL;

// Function prototypes
void show_result_window(const char *title, const char *message, gboolean is_encryption);
void load_keys();
EVP_PKEY *load_public_key(const char *filename);
EVP_PKEY *load_private_key(const char *filename);
void encrypt_message_callback(GtkWidget *widget, gpointer data);
void decrypt_message_callback(GtkWidget *widget, gpointer data);
void reload_keys_callback(GtkWidget *widget, gpointer data);
void about_dialog(GtkWidget *widget, gpointer data);
void generate_keys_callback(GtkWidget *widget, gpointer data);
void save_to_file(const char *text, const char *filename);

// Show result window
void show_result_window(const char *title, const char *message, gboolean is_encryption) {
    GtkWidget *dialog=gtk_dialog_new_with_buttons(title, NULL, GTK_DIALOG_MODAL, "Close", GTK_RESPONSE_CLOSE, NULL);
    GtkWidget *content_area=gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *message_label=gtk_label_new(message);
    gtk_box_pack_start(GTK_BOX(content_area), message_label, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Load public key from file
EVP_PKEY *load_public_key(const char *filename) {
    FILE *file=fopen(filename, "r");
    if (!file) return NULL;
    EVP_PKEY *pkey=PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

// Load private key from file
EVP_PKEY *load_private_key(const char *filename) {
    FILE *file=fopen(filename, "r");
    if (!file) return NULL;
    EVP_PKEY *pkey=PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

// Load keys if they exist in the current directory
void load_keys() {
    loaded_public_key=load_public_key("public.pem");
    loaded_private_key=load_private_key("private.pem");
}

// Save text to a file
void save_to_file(const char *text, const char *filename) {
    FILE *file=fopen(filename, "w");
    if (file) {
        fprintf(file, "%s\n", text);
        fclose(file);
    }
}

void generate_keys_callback(GtkWidget *widget, gpointer data) {
    EVP_PKEY *pkey=NULL;
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) {
        show_result_window("Error", "Key generation failed.", TRUE);
        return;
    }

    // Initialize the context for RSA key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        show_result_window("Error", "Key generation failed.", TRUE);
        return;
    }

    // Set the RSA key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        show_result_window("Error", "Key generation failed.", TRUE);
        return;
    }

    // Generate the RSA key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        show_result_window("Error", "Key generation failed.", TRUE);
        return;
    }

    // Save public key
    FILE *pub_file=fopen("public.pem", "w");
    if (!pub_file) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        show_result_window("Error", "Failed to save public key.", TRUE);
        return;
    }
    PEM_write_PUBKEY(pub_file, pkey);
    fclose(pub_file);

    // Save private key
    FILE *priv_file=fopen("private.pem", "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        show_result_window("Error", "Failed to save private key.", TRUE);
        return;
    }
    PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    // Free resources
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    show_result_window("Success", "Keys generated and saved as public.pem and private.pem.", TRUE);
}


// Encrypt message
void encrypt_message_callback(GtkWidget *widget, gpointer data) {
    const char *message=gtk_entry_get_text(GTK_ENTRY(message_entry));
    if (!loaded_public_key) {
        show_result_window("Error", "Public key not loaded.", TRUE);
        return;
    }

    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(loaded_public_key, NULL);
    if (!ctx) return;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) return;

    size_t ciphertext_len;
    EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len, (unsigned char *)message, strlen(message));
    unsigned char *ciphertext=malloc(ciphertext_len);

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, strlen(message)) <= 0) {
        free(ciphertext);
        return;
    }

    // Save the encrypted message to a file
    char *ciphertext_hex=malloc(ciphertext_len * 2 + 1);
    for (size_t i=0; i < ciphertext_len; i++) {
        sprintf(ciphertext_hex + (i * 2), "%02x", ciphertext[i]);
    }
    
    save_to_file(ciphertext_hex, "encrypted.txt"); // Save to file

    // Show success message
    show_result_window("Success", "Message encrypted and saved to encrypted.txt.", TRUE);

    // Free resources
    free(ciphertext);
    free(ciphertext_hex);
    EVP_PKEY_CTX_free(ctx);
}

// Decrypt message
void decrypt_message_callback(GtkWidget *widget, gpointer data) {
    const char *ciphertext_hex=gtk_entry_get_text(GTK_ENTRY(message_entry));
    if (!loaded_private_key) {
        show_result_window("Error", "Private key not loaded.", FALSE);
        return;
    }

    size_t ciphertext_len=strlen(ciphertext_hex) / 2;
    unsigned char *ciphertext=malloc(ciphertext_len);
    for (size_t i=0; i < ciphertext_len; i++) {
        sscanf(ciphertext_hex + (i * 2), "%2hhx", &ciphertext[i]);
    }

    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(loaded_private_key, NULL);
    if (!ctx) return;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return;

    size_t plaintext_len;
    EVP_PKEY_decrypt(ctx, NULL, &plaintext_len, ciphertext, ciphertext_len);
    unsigned char *plaintext=malloc(plaintext_len);

    if (EVP_PKEY_decrypt(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) <= 0) {
        free(plaintext);
        free(ciphertext);
        return;
    }

    // Save the decrypted message to a file
    save_to_file((char *)plaintext, "decrypted.txt"); // Save to file

    // Show success message
    show_result_window("Success", "Message decrypted and saved to decrypted.txt.", FALSE);

    // Free resources
    free(plaintext);
    free(ciphertext);
    EVP_PKEY_CTX_free(ctx);
}

// Reload keys callback
void reload_keys_callback(GtkWidget *widget, gpointer data) {
    load_keys();
}

// About dialog
void about_dialog(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog=gtk_about_dialog_new();
    gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG(dialog), "RSA Encryption Tool");
    gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(dialog), "1.0");
    gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(dialog), "End-to-End Communication\n\nThis is a simple encryption/decryption tool By Jay Mee @ J~Net 2024.");
    gtk_about_dialog_set_website(GTK_ABOUT_DIALOG(dialog), "htts://jnet.forumotion.com");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Main function
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // Load keys on startup
    load_keys();

    // Create main window
    GtkWidget *window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "RSA Encryption Tool");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Create main layout
    GtkWidget *vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Create message entry
    message_entry=gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), message_entry, FALSE, FALSE, 0);

    // Create buttons
    encrypt_button=gtk_button_new_with_label("Encrypt");
    decrypt_button=gtk_button_new_with_label("Decrypt");
    reload_button=gtk_button_new_with_label("Reload Keys");
    generate_keys_button=gtk_button_new_with_label("Generate Keys"); // New button for key generation
    about_button=gtk_button_new_with_label("About");
    
    gtk_box_pack_start(GTK_BOX(vbox), encrypt_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), decrypt_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), reload_button, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), generate_keys_button, FALSE, FALSE, 0); // Add to layout
    gtk_box_pack_start(GTK_BOX(vbox), about_button, FALSE, FALSE, 0);

    // Connect signals
    g_signal_connect(encrypt_button, "clicked", G_CALLBACK(encrypt_message_callback), NULL);
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(decrypt_message_callback), NULL);
    g_signal_connect(reload_button, "clicked", G_CALLBACK(reload_keys_callback), NULL);
    g_signal_connect(about_button, "clicked", G_CALLBACK(about_dialog), NULL);
    g_signal_connect(generate_keys_button, "clicked", G_CALLBACK(generate_keys_callback), NULL); // Connect the new button

    // Show all widgets
    gtk_widget_show_all(window);

    // Start GTK main loop
    gtk_main();

    return 0;
}

