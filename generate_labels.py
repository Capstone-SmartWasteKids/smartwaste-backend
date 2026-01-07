import os
import json

# Path ke folder dataset Anda
DATASET_PATH = 'data/sampah'
# Path untuk menyimpan file label
LABELS_PATH = 'data/labels.json'

def generate_labels_from_dataset():
    """
    Membaca nama sub-folder di dalam folder dataset sebagai label kelas.
    Mengurutkannya secara alfabet untuk memastikan konsistensi dengan model.
    """
    try:
        # Dapatkan semua nama folder di dalam path dataset
        class_names = sorted([d for d in os.listdir(DATASET_PATH) 
                              if os.path.isdir(os.path.join(DATASET_PATH, d))])
        
        if not class_names:
            print(f"Error: Tidak ada sub-folder yang ditemukan di '{DATASET_PATH}'")
            return

        # Simpan ke file JSON
        with open(LABELS_PATH, 'w') as f:
            json.dump(class_names, f, indent=4)
            
        print(f"Berhasil membuat file label di '{LABELS_PATH}'")
        print(f"Label yang ditemukan: {class_names}")

    except FileNotFoundError:
        print(f"Error: Folder dataset tidak ditemukan di '{DATASET_PATH}'")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == '__main__':
    generate_labels_from_dataset()