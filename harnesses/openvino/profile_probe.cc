#include <openvino/openvino.hpp>

#include <iostream>
#include <string>

namespace {

constexpr char kModel[] = R"IR(
<net name="ovi01-memory-probe" version="11">
    <layers>
        <layer name="input" type="Parameter" id="0" version="opset1">
            <data element_type="f32" shape="1"/>
            <output>
                <port id="0" precision="FP32"><dim>1</dim></port>
            </output>
        </layer>
        <layer name="output" type="Result" id="1" version="opset1">
            <input>
                <port id="0" precision="FP32"><dim>1</dim></port>
            </input>
        </layer>
    </layers>
    <edges>
        <edge from-layer="0" from-port="0" to-layer="1" to-port="0"/>
    </edges>
</net>
)IR";

} // namespace

int main() {
  try {
    ov::Core core;
    const auto model = core.read_model(std::string(kModel), ov::Tensor{});
    if (!model || model->get_ordered_ops().size() != 2 ||
        model->get_parameters().size() != 1 ||
        model->get_results().size() != 1) {
      std::cerr << "unexpected in-memory IR model shape\n";
      return 1;
    }
    std::cout << "OPENVINO_IR_FRONTEND_OK nodes=2 parameters=1 results=1\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "OpenVINO IR frontend probe failed: " << error.what() << '\n';
    return 1;
  }
}
