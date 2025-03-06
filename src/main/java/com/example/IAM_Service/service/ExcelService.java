package com.example.IAM_Service.service;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.mapper.UserMapper;
import com.example.IAM_Service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.apache.el.lang.ELArithmetic.isNumber;

@Service
@RequiredArgsConstructor
public class ExcelService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public List<String> importUsers(MultipartFile file) throws IOException {
        List<String> errors = new ArrayList<>();
        List<UserDto> userDtos = new ArrayList<>();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");

        if (file == null || file.isEmpty() || !file.getOriginalFilename().endsWith(".xlsx")) {
            errors.add("File dữ liệu không hợp lệ. Vui lòng tải lên file định dạng .xlsx.");
            return errors;
        }

        try (Workbook workbook = new XSSFWorkbook(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);

            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // Bỏ qua header

                try {
                    Cell usernameCell = row.getCell(1);
                    Cell emailCell = row.getCell(2);
                    Cell firstNameCell = row.getCell(3);
                    Cell lastNameCell = row.getCell(4);
                    Cell birthDateCell = row.getCell(5);
                    Cell phoneNumberCell = row.getCell(6);
                    Cell streetCell = row.getCell(7);
                    Cell wardCell = row.getCell(8);
                    Cell districtCell = row.getCell(9);
                    Cell provinceCell = row.getCell(10);
                    Cell expCell = row.getCell(11);

                    if (usernameCell == null || firstNameCell == null || lastNameCell == null) {
                        errors.add("Row " + (row.getRowNum() + 1) + ": Username hoặc Họ Tên không được để trống.");
                        continue;
                    }

                    String username = usernameCell.getStringCellValue().trim();
                    String firstName = firstNameCell.getStringCellValue().trim();
                    String lastName = lastNameCell.getStringCellValue().trim();

                    if (username.isEmpty() || firstName.isEmpty() || lastName.isEmpty()) {
                        errors.add("Row " + (row.getRowNum() + 1) + ": Username hoặc Họ Tên không được để trống.");
                        continue;
                    }
                    if (userRepository.existsByUsername(username)) {
                        errors.add("Row " + (row.getRowNum() + 1) + ": Username đã tồn tại.");
                        continue;
                    }
                    Date birthDate = null;
                    if (birthDateCell != null) {
                        if (birthDateCell.getCellType() == CellType.NUMERIC && DateUtil.isCellDateFormatted(birthDateCell)) {
                            birthDate = birthDateCell.getDateCellValue();
                        } else if (birthDateCell.getCellType() == CellType.STRING) {
                            try {
                                birthDate = new SimpleDateFormat("dd/MM/yyyy").parse(birthDateCell.getStringCellValue().trim());
                            } catch (ParseException e) {
                                errors.add("Row " + (row.getRowNum() + 1) + ": Ngày sinh không hợp lệ. Định dạng phải là dd/MM/yyyy.");
                                continue;
                            }
                        } else {
                            errors.add("Row " + (row.getRowNum() + 1) + ": Ngày sinh không hợp lệ. Định dạng phải là dd/MM/yyyy.");
                            continue;
                        }
                    }

                    String phoneNumber = "";
                    if (phoneNumberCell != null) {
                        phoneNumber = phoneNumberCell.getStringCellValue().trim();
                    }
                    String email = "";
                    if (emailCell != null) {
                        email = emailCell.getStringCellValue().trim();
                        if (!email.matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
                            errors.add("Row " + (row.getRowNum() + 1) + ": Email không hợp lệ.");
                            continue;
                        }
                    } else {
                        errors.add("Row " + (row.getRowNum() + 1) + ": Email không được trống.");
                        continue;
                    }
                    String address = (streetCell != null ? streetCell.getStringCellValue().trim() : "") + ", " + (wardCell != null ? wardCell.getStringCellValue().trim() : "") + ", " + (districtCell != null ? districtCell.getStringCellValue().trim() : "") + ", " + (provinceCell != null ? provinceCell.getStringCellValue().trim() : "");
                    Integer experienceYears = 0;
                    if (expCell != null) {
                        if (isNumber(expCell.getNumericCellValue())) {
                            experienceYears = (int) expCell.getNumericCellValue();
                        } else {
                            errors.add("Row " + (row.getRowNum() + 1) + ": Số năm kinh nghiệm phải là số.");
                            continue;
                        }
                    }

                    UserDto userDto = UserDto.builder().username(username).firstName(firstName).lastName(lastName).email(email).phoneNumber(phoneNumber).dateOfBirth(birthDate).address(address).YoE(experienceYears).build();
                    userDtos.add(userDto);

                } catch (Exception e) {
                    System.out.println(e);
                    errors.add("Row " + (row.getRowNum() + 1) + ": Dữ liệu không hợp lệ.");
                }
            }
        }

        // Lưu dữ liệu hợp lệ vào DB
        List<User> users = userMapper.toEntityList(userDtos);
        userRepository.saveAll(users);
        return errors;
    }


    public byte[] exportUsers() throws IOException {
        List<UserDto> users = userMapper.toDtoList(userRepository.findAll());
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy"); //Format ngày tháng

        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("Users");
            Row header = sheet.createRow(0);
            header.setHeightInPoints(25); //Tăng chiều cao tiêu đề

            String[] columns = {"STT", "Full Name", "Username", "Email", "PhoneNumber", "DoB", "Address", " Years of Experience", "Account Status"};

            // Định dạng tiêu đề: Nền xanh dương, chữ trắng, in đậm, cỡ chữ lớn
            CellStyle headerStyle = workbook.createCellStyle();
            Font headerFont = workbook.createFont();
            headerFont.setBold(true);
            headerFont.setColor(IndexedColors.WHITE.getIndex()); // Chữ trắng
            headerFont.setFontHeightInPoints((short) 14); // 🔹 Tăng cỡ chữ tiêu đề
            headerStyle.setFont(headerFont);
            headerStyle.setFillForegroundColor(IndexedColors.BLUE.getIndex()); // Nền xanh dương
            headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
            headerStyle.setAlignment(HorizontalAlignment.CENTER);
            headerStyle.setVerticalAlignment(VerticalAlignment.CENTER); // 🔹 Căn giữa dọc
            headerStyle.setBorderTop(BorderStyle.MEDIUM);
            headerStyle.setBorderBottom(BorderStyle.MEDIUM);
            headerStyle.setBorderLeft(BorderStyle.THIN);
            headerStyle.setBorderRight(BorderStyle.THIN);

            // Style cho cell
            CellStyle dataStyle = workbook.createCellStyle();
            dataStyle.setAlignment(HorizontalAlignment.CENTER);

            // Tạo tiêu đề với style
            for (int i = 0; i < columns.length; i++) {
                Cell cell = header.createCell(i);
                cell.setCellValue(columns[i]);
                cell.setCellStyle(headerStyle);
            }

            int rowIdx = 1;
            for (UserDto user : users) {
                Row row = sheet.createRow(rowIdx++);
                row.setHeightInPoints(20); // 🔹 Tăng chiều cao dòng dữ liệu
                row.createCell(0).setCellValue(rowIdx - 1);
                row.createCell(1).setCellValue(user.getFirstName() + " " + user.getLastName());
                row.createCell(2).setCellValue(user.getUsername());
                row.createCell(3).setCellValue(user.getEmail());
                row.createCell(4).setCellValue(user.getPhoneNumber());

                // 🔹 Xử lý Date thành String với format dd/MM/yyyy
                String formattedDate = (user.getDateOfBirth() != null) ? dateFormat.format(user.getDateOfBirth()) : "";
                row.createCell(5).setCellValue(formattedDate);

                row.createCell(6).setCellValue(user.getAddress());
                row.createCell(7).setCellValue(user.getYoE());
                row.createCell(8).setCellValue(user.getIsActive() ? "Active" : "Not Active");

                for (int i = 0; i < columns.length; i++) {
                    row.getCell(i).setCellStyle(dataStyle);
                }
            }

            // Tự động điều chỉnh kích thước cột
            for (int i = 0; i < columns.length; i++) {
                sheet.autoSizeColumn(i);
                sheet.setColumnWidth(i, sheet.getColumnWidth(i) + 512); // Thêm 2 đơn vị (~2 ký tự)
            }

            // Xuất file ra mảng byte[]
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            workbook.write(outputStream);
            return outputStream.toByteArray();
        }
    }
}
