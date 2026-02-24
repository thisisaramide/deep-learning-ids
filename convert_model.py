from tensorflow.keras.models import load_model

print("Loading old model...")
model = load_model('ids_autoencoder_85percent.h5', compile=False)

print("Re-saving in new format...")
model.save('ids_autoencoder_85percent.keras')

print("✅ Model converted successfully!")
print("   New file: ids_autoencoder_85percent.keras")