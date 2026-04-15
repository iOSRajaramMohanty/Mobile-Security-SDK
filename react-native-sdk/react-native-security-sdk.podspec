require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name = 'react-native-security-sdk'
  s.version = package['version']
  s.summary = package['description']
  s.license = package['license']
  s.authors = { 'Mobile Security SDK' => 'security@example.com' }
  s.homepage = 'https://example.com/mobile-security-sdk'
  s.source = { :git => 'https://example.com/mobile-security-sdk.git', :tag => "v#{s.version}" }

  s.platforms = { :ios => '15.0' }
  s.source_files = 'ios/**/*.{h,m,mm,swift}', '../ios-sdk/Sources/SecuritySDK/**/*.swift'
  s.requires_arc = true
  s.pod_target_xcconfig = {
    'SWIFT_VERSION' => '5.9',
    'DEFINES_MODULE' => 'YES'
  }

  s.dependency 'React-Core'
end
