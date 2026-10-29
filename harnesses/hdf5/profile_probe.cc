#include <hdf5.h>
#include <hdf5_hl.h>

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace {

class Handle {
public:
  using Close = herr_t (*)(hid_t);

  Handle() = default;
  Handle(hid_t id, Close close) : id_(id), close_(close) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept
      : id_(other.id_), close_(other.close_) {
    other.id_ = H5I_INVALID_HID;
  }
  Handle &operator=(Handle &&other) noexcept {
    if (this != &other) {
      reset();
      id_ = other.id_;
      close_ = other.close_;
      other.id_ = H5I_INVALID_HID;
    }
    return *this;
  }
  ~Handle() { reset(); }

  [[nodiscard]] hid_t get() const { return id_; }
  [[nodiscard]] bool valid() const { return id_ >= 0; }

  void reset() {
    if (valid() && close_ != nullptr) {
      (void)close_(id_);
    }
    id_ = H5I_INVALID_HID;
  }

private:
  hid_t id_ = H5I_INVALID_HID;
  Close close_ = nullptr;
};

int fail(const std::string &message) {
  std::cerr << "HDF5 file-image probe failed: " << message << '\n';
  return 1;
}

int filter_available(H5Z_filter_t filter) {
  const htri_t available = H5Zfilter_avail(filter);
  return available < 0 ? -1 : (available > 0 ? 1 : 0);
}

} // namespace

int main() {
  if (H5Eset_auto2(H5E_DEFAULT, nullptr, nullptr) < 0) {
    return fail("could not disable expected negative-control error output");
  }

  unsigned major = 0;
  unsigned minor = 0;
  unsigned release = 0;
  if (H5get_libversion(&major, &minor, &release) < 0 || major != 2U ||
      minor != 2U || release != 0U) {
    return fail("runtime library is not HDF5 2.2.0");
  }

  Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
  if (!fapl.valid() || H5Pset_fapl_core(fapl.get(), 64U * 1024U, false) < 0) {
    return fail("could not configure the in-memory core driver");
  }
  Handle created(H5Fcreate("hdf5_profile_probe", H5F_ACC_TRUNC, H5P_DEFAULT,
                           fapl.get()),
                 H5Fclose);
  if (!created.valid()) {
    return fail("could not create the in-memory HDF5 image");
  }
  Handle group(H5Gcreate2(created.get(), "weights", H5P_DEFAULT, H5P_DEFAULT,
                          H5P_DEFAULT),
               H5Gclose);
  if (!group.valid() || H5Fflush(created.get(), H5F_SCOPE_GLOBAL) < 0) {
    return fail("could not create and flush the probe group");
  }

  const ssize_t image_size = H5Fget_file_image(created.get(), nullptr, 0);
  if (image_size <= 0) {
    return fail("could not measure the generated file image");
  }
  const auto size = static_cast<std::size_t>(image_size);
  std::vector<unsigned char> image(size);
  const ssize_t copied = H5Fget_file_image(created.get(), image.data(), size);
  if (copied != image_size) {
    return fail("could not copy the generated file image");
  }
  group.reset();
  created.reset();
  fapl.reset();

  unsigned calls = 0;
  Handle opened(H5LTopen_file_image(image.data(), image.size(), 0), H5Fclose);
  ++calls;
  if (!opened.valid()) {
    return fail("H5LTopen_file_image rejected the valid image");
  }
  unsigned intent = H5F_ACC_RDWR;
  if (H5Fget_intent(opened.get(), &intent) < 0 ||
      (intent & H5F_ACC_RDWR) != 0U) {
    return fail("flags 0 did not produce a read-only file image");
  }
  const htri_t has_group = H5Lexists(opened.get(), "weights", H5P_DEFAULT);
  if (has_group != 1) {
    return fail("reopened file image does not contain the probe group");
  }
  opened.reset();

  const hid_t null_result = H5LTopen_file_image(nullptr, image.size(), 0);
  ++calls;
  if (null_result >= 0) {
    (void)H5Fclose(null_result);
    return fail("H5LTopen_file_image accepted a null buffer");
  }
  const hid_t zero_result = H5LTopen_file_image(image.data(), 0, 0);
  ++calls;
  if (zero_result >= 0) {
    (void)H5Fclose(zero_result);
    return fail("H5LTopen_file_image accepted a zero-sized buffer");
  }

  const int deflate = filter_available(H5Z_FILTER_DEFLATE);
  const int szip = filter_available(H5Z_FILTER_SZIP);
  const int shuffle = filter_available(H5Z_FILTER_SHUFFLE);
  const int fletcher32 = filter_available(H5Z_FILTER_FLETCHER32);
  const int nbit = filter_available(H5Z_FILTER_NBIT);
  const int scaleoffset = filter_available(H5Z_FILTER_SCALEOFFSET);
  if (deflate != 0 || szip != 0 || shuffle != 1 || fletcher32 != 1 ||
      nbit != 1 || scaleoffset != 1) {
    return fail("runtime filter availability differs from the HDF-01 contract");
  }

  std::cout << "HDF5_FILE_IMAGE_OK calls=" << calls
            << " readonly=1 group=1 deflate=" << deflate
            << " szip=" << szip << " shuffle=" << shuffle
            << " fletcher32=" << fletcher32 << " nbit=" << nbit
            << " scaleoffset=" << scaleoffset << " version=" << major << '.'
            << minor << '.' << release << '\n';
  return 0;
}
