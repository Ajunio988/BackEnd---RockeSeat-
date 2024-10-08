const fs = require("fs");
const path = require("path");
const uploadConfig = require("../src/configs/upload");

class DiskStorage {
  async saveFile(file) {
    await fs.promises.rename(
      path.rename(uploadConfig.TMP_FOLDER, file),
      path.rename(uploadConfig.UPLOADS_FOLDER, file)
    );

    return file;
  }

  async deleteFile(file) {
    const filePath = path.resolve(uploadConfig.UPLOADS_FOLDER, file);

    try {
      await fs.promises.stat(filePath);
    } catch {
      return;
    }

    await fs.promises.unlink(filePath)
  }
}

module.exports = DiskStorage